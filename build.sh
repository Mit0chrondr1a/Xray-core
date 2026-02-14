#!/bin/bash
set -euo pipefail

# Xray-core optimized build script
# Target: Linux amd64/arm64
#
# Performance optimizations:
#   - TCP_NODELAY on all TCP sockets
#   - Zero-alloc IsCompleteRecord for Vision
#   - Uplink + downlink splice for Vision and Trojan
#   - Fast math/rand/v2 PRNG for Vision padding
#   - recvmmsg(2) batch UDP reads (64 packets/syscall)
#   - kTLS kernel offload (AES-128/256-GCM, ChaCha20-Poly1305)
#   - eBPF XDP + sockmap programs
#   - Configurable TLS session cache (XRAY_TLS_CACHE_SIZE env)
#   - [XRAY_CGO=1] Rust-accelerated TLS via rustls + native kTLS
#   - [XRAY_CGO=1] Rust-accelerated Blake3 KDF, MPH domain matcher, GeoIP matcher, Vision padding
#
# Usage:
#   ./build.sh              # Build for current platform (Rust+musl, requires zig + cargo)
#   ./build.sh amd64        # Build for amd64 (GOAMD64=v3, AVX2 required)
#   ./build.sh arm64        # Cross-compile arm64 with Rust+musl
#   XRAY_CGO=0 ./build.sh          # Pure Go static binary (no Rust)
#   ZIG=/path/to/zig ./build.sh    # Override zig binary path

GO="${GO:-go}"
ZIG="${ZIG:-zig}"
OUTNAME="xray"
GOARCH="${1:-amd64}"
GOOS="linux"

# Detect host platform for cross-compilation.
HOST_GOOS=""
case "$(uname -s)" in
    Linux)  HOST_GOOS="linux" ;;
    Darwin) HOST_GOOS="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) HOST_GOOS="windows" ;;
esac

HOST_GOARCH=""
case "$(uname -m)" in
    x86_64)  HOST_GOARCH="amd64" ;;
    aarch64) HOST_GOARCH="arm64" ;;
esac

# Fallback to go env if uname mapping did not determine host platform.
if [ -z "$HOST_GOOS" ]; then
    HOST_GOOS=$("$GO" env GOOS 2>/dev/null || true)
fi
if [ -z "$HOST_GOARCH" ]; then
    HOST_GOARCH=$("$GO" env GOARCH 2>/dev/null || true)
fi

IS_CROSS_BUILD=0
if [ "$GOOS" != "$HOST_GOOS" ] || [ "$GOARCH" != "$HOST_GOARCH" ]; then
    IS_CROSS_BUILD=1
fi

COMMID=$(git describe --always --dirty 2>/dev/null || echo "dev")
LDFLAGS="-s -w -buildid= -X github.com/xtls/xray-core/core.build=${COMMID}"
BUILDFLAGS="-trimpath -buildvcs=false"
GCFLAGS="all=-l=4"
PGOFLAGS="-pgo=main/default.pgo"

if [ "$GOARCH" = "amd64" ]; then
    export GOAMD64=v3  # AVX2, BMI1/2, FMA — requires Haswell+ or Zen+
fi

USE_CGO="${XRAY_CGO:-1}"

if [ "$USE_CGO" = "1" ] && ! command -v cargo &>/dev/null; then
    echo "Warning: cargo not found, falling back to pure Go"
    USE_CGO="0"
fi

if [ "$USE_CGO" = "1" ]; then
    # Zig-only toolchain policy — no gcc/musl-gcc fallback.
    if [ -n "${CC:-}" ] || [ -n "${CXX:-}" ]; then
        echo "Error: CC/CXX overrides are disabled; set ZIG=/path/to/zig instead" >&2
        exit 1
    fi

    # Map GOOS/GOARCH to Rust and zig target triples (musl for static linking).
    RUST_TARGET=""
    ZIG_TARGET=""
    case "${GOOS}-${GOARCH}" in
        linux-amd64)
            RUST_TARGET="x86_64-unknown-linux-musl"
            ZIG_TARGET="x86_64-linux-musl"
            ;;
        linux-arm64)
            RUST_TARGET="aarch64-unknown-linux-musl"
            ZIG_TARGET="aarch64-linux-musl"
            ;;
        *)
            echo "Warning: no Rust target for ${GOOS}/${GOARCH}, falling back to pure Go"
            USE_CGO="0"
            ;;
    esac
fi

if [ "$USE_CGO" = "1" ]; then
    # Require zig for the musl C toolchain.
    ZIG_BIN=""
    if ! ZIG_BIN="$(command -v "$ZIG" 2>/dev/null)"; then
        echo "Error: zig is required for XRAY_CGO=1 (missing: ${ZIG})" >&2
        exit 1
    fi
    echo "Using zig toolchain: ${ZIG_BIN} (target: ${ZIG_TARGET})"

    # Generate zig wrapper scripts that strip --target= flags from cc-rs.
    # cc-rs passes Rust-style triples (--target=x86_64-unknown-linux-musl)
    # that zig doesn't parse; the wrapper rewrites to zig's -target format.
    CARGO_CC_WRAPPER="$(mktemp "${TMPDIR:-/tmp}/xray-zig-cc.XXXXXX")"
    CARGO_CXX_WRAPPER="$(mktemp "${TMPDIR:-/tmp}/xray-zig-cxx.XXXXXX")"
    trap 'rm -f "${CARGO_CC_WRAPPER:-}" "${CARGO_CXX_WRAPPER:-}"' EXIT

    for wrapper_info in "cc:${CARGO_CC_WRAPPER}" "c++:${CARGO_CXX_WRAPPER}"; do
        mode="${wrapper_info%%:*}"
        wrapper="${wrapper_info#*:}"
        cat >"$wrapper" <<'WEOF'
#!/usr/bin/env bash
set -euo pipefail
args=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --target=*) shift ;;
        --target)   shift; [ "$#" -gt 0 ] && shift ;;
        *)          args+=("$1"); shift ;;
    esac
done
WEOF
        echo "exec \"\${XRAY_ZIG_BIN}\" ${mode} -target \"\${XRAY_ZIG_TARGET}\" \"\${args[@]}\"" >>"$wrapper"
        chmod +x "$wrapper"
    done

    # Set target-cpu for SIMD — matches GOAMD64=v3 on the Go side.
    RUST_CPU_FLAGS=""
    case "$GOARCH" in
        amd64) RUST_CPU_FLAGS="-C target-cpu=x86-64-v3" ;;
        arm64) RUST_CPU_FLAGS="-C target-cpu=cortex-a53" ;;
    esac

    # Step 0: Build eBPF programs for the BPF virtual machine.
    #
    # eBPF programs run inside the Linux kernel, not on a real CPU. They require:
    #   - Nightly Rust: build-std=core rebuilds libcore for the bpfel target
    #   - bpf-linker:   specialized LLVM linker that emits BTF (BPF Type Format)
    #                    sections the kernel verifier requires; standard linkers
    #                    (GNU ld, LLVM lld) cannot produce valid eBPF ELF
    #
    # Target, build-std, and linker are configured in rust/xray-ebpf/.cargo/config.toml
    # so `cargo +nightly build` is all that's needed here.
    #
    # The compiled bytecode is embedded in the userspace crate (xray-rust) via
    # include_bytes_aligned! at compile time when --features ebpf-bytecode is set.
    EBPF_FEATURES=""
    EBPF_BYTECODE="rust/xray-ebpf/target/bpfel-unknown-none/release/xray-ebpf"

    # Remove stale eBPF bytecode before building to prevent include_bytes!
    # from silently embedding an outdated binary when the build is skipped or fails.
    rm -f "$EBPF_BYTECODE"

    if command -v rustup &>/dev/null; then
        # Ensure nightly toolchain is installed and up-to-date.
        # A stale nightly can break bpf-linker due to LLVM ABI changes.
        if rustup toolchain list | grep -q nightly; then
            echo "Updating nightly toolchain..."
            rustup update nightly 2>&1 | tail -1 || true
        else
            echo "Installing nightly toolchain (required for eBPF)..."
            if ! rustup toolchain install nightly 2>&1 | tail -1; then
                echo "Warning: failed to install nightly, skipping eBPF build"
            fi
        fi

        if rustup toolchain list | grep -q nightly; then
            # Resolve the nightly toolchain's bin directory so we can put it
            # first on PATH. This is necessary when a standalone rustc (e.g.
            # Homebrew's rust formula) shadows rustup's proxies — `rustup run
            # nightly` sets RUSTUP_TOOLCHAIN but doesn't modify PATH, so
            # cargo's sub-process invocations of rustc would find the stable
            # system compiler instead.
            NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc 2>/dev/null || true)"
            NIGHTLY_BIN_DIR=""
            if [ -n "$NIGHTLY_RUSTC" ]; then
                NIGHTLY_BIN_DIR="$(dirname "$NIGHTLY_RUSTC")"
            fi

            if [ -z "$NIGHTLY_BIN_DIR" ]; then
                echo "Warning: cannot locate nightly rustc, skipping eBPF build"
            else
                # Install/update bpf-linker — must be compiled against the
                # current nightly's LLVM. cargo install is a no-op if the
                # installed version already matches the latest crate release.
                if ! command -v bpf-linker &>/dev/null; then
                    echo "Installing bpf-linker (required for eBPF)..."
                    if ! PATH="${NIGHTLY_BIN_DIR}:${PATH}" cargo install bpf-linker 2>&1 | tail -3; then
                        echo "Warning: bpf-linker install failed, skipping eBPF build"
                    fi
                fi

                if command -v bpf-linker &>/dev/null; then
                    echo "Building eBPF programs (bpfel-unknown-none via bpf-linker)..."
                    if PATH="${NIGHTLY_BIN_DIR}:${PATH}" cargo build \
                        --release \
                        --manifest-path rust/xray-ebpf/Cargo.toml \
                        --target-dir rust/xray-ebpf/target; then
                        EBPF_FEATURES="--features ebpf-bytecode"
                        echo "eBPF programs built successfully"
                    else
                        echo "Warning: eBPF build failed (non-fatal), continuing without SK_MSG cork + Aya"
                    fi
                fi
            fi
        fi
    else
        echo "Warning: rustup not found, skipping eBPF build"
        echo "  Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    fi

    # Build Rust static library for the musl target.
    # -Z build-std rebuilds std from source so we don't need a pre-installed
    # musl sysroot. RUSTC_BOOTSTRAP=1 allows this on stable rustc.
    echo "Building Rust components for ${RUST_TARGET}..."
    RUST_TARGET_ENV="${RUST_TARGET//-/_}"
    RUST_TARGET_ENV_UPPER="${RUST_TARGET_ENV^^}"

    env \
        "XRAY_ZIG_BIN=${ZIG_BIN}" \
        "XRAY_ZIG_TARGET=${ZIG_TARGET}" \
        "CC_${RUST_TARGET_ENV}=${CARGO_CC_WRAPPER}" \
        "CXX_${RUST_TARGET_ENV}=${CARGO_CXX_WRAPPER}" \
        "CARGO_TARGET_${RUST_TARGET_ENV_UPPER}_LINKER=${CARGO_CC_WRAPPER}" \
        RUSTC_BOOTSTRAP="${RUSTC_BOOTSTRAP:-1}" \
        RUSTFLAGS="${RUSTFLAGS:-} ${RUST_CPU_FLAGS}" \
        cargo build -Z build-std=std,panic_abort --release \
            --manifest-path rust/xray-rust/Cargo.toml \
            --target "$RUST_TARGET" \
            --target-dir rust/xray-rust/target \
            ${EBPF_FEATURES}

    RUST_LIB_PATH="rust/xray-rust/target/${RUST_TARGET}/release/libxray_rust.a"
    if [ ! -f "$RUST_LIB_PATH" ]; then
        echo "Error: missing Rust static library at ${RUST_LIB_PATH}" >&2
        exit 1
    fi

    # cgo.go expects target/release/; copy from the target-specific directory.
    # Remove any stale copy first to prevent linking an outdated library if
    # a previous build targeted a different architecture or feature set.
    mkdir -p rust/xray-rust/target/release
    rm -f rust/xray-rust/target/release/libxray_rust.a
    install -m 644 "$RUST_LIB_PATH" rust/xray-rust/target/release/libxray_rust.a
    echo "Rust library: $(ls -lh rust/xray-rust/target/release/libxray_rust.a | awk '{print $5}')"

    # Set zig as the C/C++ compiler for Go's CGO step.
    export CC="${ZIG_BIN} cc -target ${ZIG_TARGET}"
    export CXX="${ZIG_BIN} c++ -target ${ZIG_TARGET}"

    # Produce a fully static binary on Linux:
    # -lunwind: Rust's panic runtime needs libunwind when statically linked.
    # -linkmode external: Go invokes zig directly (internal linker mishandles
    #   .dynsym when targeting musl).
    # -extldflags '-static -s': tell zig to produce a static binary.
    export CGO_LDFLAGS="${CGO_LDFLAGS:-} -lunwind"
    LDFLAGS="${LDFLAGS} -linkmode external -extldflags '-static -s'"
fi

echo "Building Xray-core for ${GOOS}/${GOARCH} (${COMMID}, CGO=${USE_CGO})..."
CGO_ENABLED="$USE_CGO" GOOS="$GOOS" GOARCH="$GOARCH" \
    "$GO" build -o "$OUTNAME" $BUILDFLAGS $PGOFLAGS -gcflags="$GCFLAGS" -ldflags="$LDFLAGS" ./main/

echo "Done: $(ls -lh $OUTNAME | awk '{print $5}')"
if [ "$USE_CGO" = "1" ]; then
    echo "  Rust-accelerated (static musl): TLS, REALITY, kTLS, Blake3 KDF, MPH matcher, GeoIP matcher, Vision padding"
    if [ -n "${EBPF_FEATURES:-}" ]; then
        echo "  eBPF: Aya sockmap + SK_MSG cork + pinned maps"
    else
        echo "  eBPF: Go fallback (no nightly toolchain for Aya)"
    fi
else
    echo "  Pure Go static binary"
fi
file "$OUTNAME"
