# Loopback Native REALITY Best Practice

Date: 2026-03-24

## Purpose

This document consolidates the fd-ownership boundary lesson from the DeferredRustConn / loopback native REALITY investigation.

It is the practical rulebook for future work involving cross-runtime fd management, not just a postmortem.

## Core Principle

When Rust owns a socket fd's blocking mode, Go's runtime contracts break.

Loopback amplifies this because zero RTT removes the natural serialization that masks the hazard on remote connections.

## What We Learned

### 1. BlockingGuard changes the shared file description, not just the dup'd fd

`BlockingGuard` (`fdutil.rs:243`) clears `O_NONBLOCK` on a dup'd fd. Because `fcntl(F_SETFL)` operates on the **file description** (kernel-level, shared between all fds pointing to the same open file), the original Go-owned fd becomes blocking too.

This is session-lifetime state, not per-call state. The guard is created once, moved into `DeferredSession` (`reality.rs:1281`), and stays there until detach or explicit restore.

### 2. Go's deadline mechanism cannot interrupt kernel-blocked Rust reads

Go's `SetReadDeadline` / `SetWriteDeadline` work through the runtime poller (epoll). When a deadline fires, Go's runtime wakes the parked goroutine by injecting an error into the poller.

With DeferredRustConn:
- `Read()` calls through CGO into Rust's `deferred_read()`
- Rust reads from the dup'd fd, which is blocking (`O_NONBLOCK` cleared)
- If no data is available, the read blocks the OS thread in a kernel syscall
- Go's deadline timer fires but **cannot interrupt a kernel-blocked OS thread**

Go passes deadlines into Rust via `cgo.go:1039`, but the Rust read path only honors them in the `WouldBlock -> poll(deadline)` path (`tls.rs:796-828`). With `O_NONBLOCK` still cleared, the first `libc::read` (`tls.rs:802`) blocks in the kernel before that deadline machinery ever runs.

The poll-based deadline compatibility is designed for the post-`RestoreNonBlock` case (`tls.rs:958`), not normal pre-detach operation.

### 3. Loopback amplifies the hazard because idle periods cause indefinite blocks

On a **remote connection** (50-200ms RTT), data arrives frequently — TCP keepalives, mux heartbeats, application traffic. The blocking read almost never actually blocks for long.

On **loopback** (0ms RTT), all data transfers complete in microseconds. When the connection goes truly idle between bursts, the Rust read blocks indefinitely in the kernel. Go's deadline cannot break it. The mux reader goroutine hangs, and all multiplexed streams (DNS, IG, YouTube) fail.

### 4. The symptom is invisible to the server

Server-side pipeline metrics showed 99.7% success: all `pipeline-summary` entries reported data transferred, splice working, zero breaker trips. The server writes data correctly to the socket. The failure manifests only at the client, which sees erratic mux responsiveness.

### 5. Existing mitigation code is scoped to post-detach, not pre-detach

- `RestoreNonBlock` exists in `reality.rs:1503` and `tls.go:1725`
- `read_exact_with_poll()` deadline machinery exists in `tls.rs:796-828`
- Both are designed for the post-`RestoreNonBlock` state (Vision cmd=2 detach path)
- During normal pre-detach operation, the fd is blocking and the deadline code path is unreachable

## Branch Rules

### Rule 1: Loopback AUTO must skip native REALITY

Guard location: `transport/internet/tcp/native_policy.go` (reason: `loopback_listener_auto_guard`).

The guard applies to both loopback listeners and loopback local addresses when policy mode is `AUTO`.

`PREFER_NATIVE` and `FORCE_NATIVE` remain available as explicit opt-in for testing.

### Rule 2: Do not remove the loopback guard without solving the fd-ownership boundary

The guard is not a workaround — it is a correct architectural boundary. Removing it requires one of:
- Making Rust honor Go-passed deadlines **before** the first `libc::read` (not only in the post-`RestoreNonBlock` poll path)
- Restructuring `BlockingGuard` to not clear `O_NONBLOCK` on the shared file description
- Using a separate fd (not dup'd from the same file description) for Rust operations

Any of these is significant plumbing for a path that has no production value (loopback is testing only).

### Rule 3: When server logs show success but clients report failure, suspect fd-ownership boundaries

The characteristic symptom pattern:
- Server-side pipeline metrics: 99%+ success
- Client-side: intermittent failures, mux churn, app-level timeouts
- Failures cluster on loopback or low-latency paths
- Restoring Go-only TLS immediately resolves symptoms

This pattern indicates the server is writing data correctly but the client's read path is disrupted by fd-level state changes invisible to the server's write path.

### Rule 4: Cross-runtime fd sharing is safe only when network RTT provides natural serialization

DeferredRustConn's fd-ownership model works on remote connections because:
- Network RTT (50-200ms) dwarfs any fd-state transition time
- Reads rarely block indefinitely (traffic cadence prevents it)
- The race window between Go's poller expectations and Rust's blocking state is negligible

This safety property does not hold on loopback.

## Relationship to DNS Best Practice

This document shares a key lesson with `dns-best-practice-2026-03-06.md`:

> REALITY native deferred handover on loopback must not be the AUTO default.

The DNS document arrived at this rule from observing DNS UX regressions. This document provides the underlying mechanism: the fd-ownership boundary violation that causes those regressions.

Both documents agree on the same guard, for complementary reasons:
- DNS doc: control-plane traffic must not depend on fragile Vision/mux fast paths on loopback
- This doc: DeferredRustConn's blocking fd breaks Go's deadline contracts on loopback

## Key Code Locations

| Location | Role |
|----------|------|
| `rust/xray-rust/src/fdutil.rs:243` | `BlockingGuard::new()` — clears `O_NONBLOCK` |
| `rust/xray-rust/src/fdutil.rs:293` | Guard moved into `DeferredSession` |
| `rust/xray-rust/src/reality.rs:1281` | DeferredSession holds guard for session lifetime |
| `rust/xray-rust/src/reality.rs:1503` | `restore_nonblock` — post-detach mitigation |
| `rust/xray-rust/src/tls.rs:796-828` | `read_exact_with_poll()` — deadline-aware, post-restore only |
| `rust/xray-rust/src/tls.rs:802` | First `libc::read` — blocks if `O_NONBLOCK` cleared |
| `transport/internet/tls/tls.go:1725` | Go-side `RestoreNonBlock` |
| `transport/internet/tcp/native_policy.go` | Loopback AUTO guard |
| `common/native/cgo.go:1039` | Go passes deadlines into Rust FFI |

## Timeline

- **2026-03-03**: Loopback Vision acceleration disabled after UX freeze episodes (vision-loopback-decision doc)
- **2026-03-06**: DNS best practice codified — loopback AUTO guard as operational rule
- **2026-03-14**: Native REALITY retreat — loopback guard retained in slim slice
- **2026-03-24**: Loopback guard accidentally removed during working-tree iteration
- **2026-03-24**: IG/YouTube refresh failures on canary — server pipeline 99.7% clean
- **2026-03-24**: Guard restored — symptoms immediately resolved
- **2026-03-24**: Root cause identified: session-lifetime blocking fd breaks Go deadline contracts on loopback
- **2026-03-24**: Guard designated permanent for AUTO mode
