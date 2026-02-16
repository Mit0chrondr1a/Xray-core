# Xray-core

Go network proxy platform with Rust FFI acceleration and eBPF kernel offload.

## Build System

Uses `Taskfile.yaml` + `mise` for toolchain management. **Do not look for `build.sh` — it no longer exists.**

| Command | Description |
|---------|-------------|
| `task build` | CGO+Rust build (default, amd64) |
| `task arm64` | CGO+Rust build for ARM64 |
| `task build-pure-go` | Pure Go, no Rust/zig (`CGO_ENABLED=0`) |
| `task build-rust` | Rust staticlib only (`libxray_rust.a`) |
| `task build-ebpf` | eBPF bytecode only (requires nightly + bpf-linker) |
| `task update` | Update all Go + Rust dependencies |

## Architecture

- **Go core:** VLESS, VMess, Trojan, Shadowsocks, WireGuard, Hysteria protocols
- **Rust FFI** (`rust/xray-rust/`): accelerated Blake3, MPH matcher, GeoIP matcher, TLS/REALITY, Vision padding, eBPF loader
- **eBPF** (`rust/xray-ebpf/`): SK_SKB + SK_MSG programs for kernel-level socket splicing and send-path cork batching
- **FFI bridge:** `common/native/cgo.go` (CGO path) and `common/native/purego.go` (pure-Go fallback)

## eBPF Build Pitfalls

The eBPF build has three environment hazards that cause confusing failures:

1. **bpf-linker PATH shadowing:** Nix may install an older `bpf-linker` linked against LLVM 21 that shadows `~/.cargo/bin/bpf-linker` (LLVM 22). Symptoms: SIGSEGV in the SROA pass, or `Unknown attribute kind (Producer LLVM22 / Reader LLVM21)`. The Taskfile mitigates this by resolving `$HOME/.cargo/bin/bpf-linker` explicitly via `CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER`.

2. **`RUSTUP_TOOLCHAIN` vs mise:** mise exports `RUSTUP_TOOLCHAIN=stable`. Setting it to `""` in go-task exports an empty string (not unset), which may prevent rustup from reading `rust-toolchain.toml`. The Taskfile parses the channel from `rust-toolchain.toml` and exports `RUSTUP_TOOLCHAIN` explicitly.

3. **bpf-linker must match the pinned nightly's LLVM:** After bumping the nightly pin in `rust/xray-ebpf/rust-toolchain.toml`, always reinstall bpf-linker:
   ```bash
   RUSTUP_TOOLCHAIN=<new-nightly> cargo install bpf-linker --force
   ```

**Debugging tip:** When a linker segfaults, run `which <linker>` before blaming the compiler — PATH shadowing is the most common cause.

## Testing

```bash
go test ./...                              # pure-Go tests
CGO_ENABLED=1 XRAY_CGO=1 go test ./common/...  # CGO+Rust tests
```

- `app/router/` tests require an external `geoip.dat` file
- Both CGO_ENABLED=0 and CGO_ENABLED=1 must pass `./common/...` tests
- Do not edit `.pb.go` files — they are generated from protobuf

## Key Paths

| Path | Purpose |
|------|---------|
| `Taskfile.yaml` | Build system entry point |
| `mise.toml` | Toolchain versions (Go, Zig, Rust) |
| `rust/xray-rust/` | Userspace Rust crate (staticlib) |
| `rust/xray-ebpf/` | eBPF crate (bpfel-unknown-none target) |
| `common/native/cgo.go` | Go→Rust FFI bindings |
| `common/native/purego.go` | Pure-Go fallback implementations |
| `main/default.pgo` | PGO profile for guided optimization |
