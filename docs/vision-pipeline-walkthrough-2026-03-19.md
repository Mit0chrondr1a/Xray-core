# Vision Pipeline Walkthrough — 2026-03-19

## Purpose

This document is a consolidated walkthrough of the Vision padding protocol as
implemented on the `perf` branch, covering each phase's execution model,
acceleration surface, and Rustification constraints. It serves as a reference
for understanding why specific acceleration decisions were made and what
tradeoffs they carry.

Snapshot: `perf` branch at `f5a28e50`.

Related documents:

- [ebpf-vision-analysis.md](ebpf-vision-analysis.md) — eBPF/sockmap exclusion
- [ktls-vision-incompatibility.md](ktls-vision-incompatibility.md) — kTLS/Vision rule
- [native-reality-failure-genealogy-2026-03-19.md](native-reality-failure-genealogy-2026-03-19.md) — the refactoring failure

---

## I. Protocol Overview

Vision is a traffic obfuscation protocol layered inside VLESS. It exists to make
proxied connections look like normal HTTPS by padding early records and then
optionally stripping the outer TLS layer mid-connection.

### The Three Commands

| Command | Byte | Meaning | Subsequent behavior |
|---------|------|---------|---------------------|
| cmd=0 | `0x00` | Continue padding | Loop: read next padding block |
| cmd=1 | `0x01` | End padding, keep TLS | Steady-state userspace TLS streaming |
| cmd=2 | `0x02` | End padding, strip TLS | Detach TLS, switch to raw socket |

### The Framing Format

Each padding block has a 5-byte header:

```
[command: 1 byte] [content_length: 2 bytes BE] [padding_length: 2 bytes BE]
```

Preceded on the very first block by a 16-byte user UUID for authentication.
After the header, `content_length` bytes of real data, then `padding_length`
bytes of random padding (discarded by the receiver).

---

## II. Phase-by-Phase Execution

### Phase 0: Handshake (Before Vision)

**Code**: `transport/internet/tcp/hub.go:374-500` (REALITY),
`transport/internet/tcp/hub.go:349-373` (TLS)

**What happens**: TLS or REALITY handshake completes. For REALITY connections,
the AUTO policy (`native_policy.go:649`) decides whether to use Rust
(`DeferredRustConn`) or Go (`reality.Server()`).

**Canonical deployment**: AUTO + loopback → Go REALITY → `*reality.Conn`.
Rust is never activated for Vision traffic in the canonical deployment.

**Non-canonical (PREFER_NATIVE/FORCE_NATIVE or non-loopback)**: Rust REALITY →
`DeferredRustConn`. Vision padding will then execute through CGO.

**Acceleration**: Rust handshake is a clean, contained operation. Sound ROI
regardless of deployment shape. The ROI question is about what happens AFTER
the handshake.

### Phase 1: Vision Padding (cmd=0)

**Code**: `proxy/proxy.go:755-850` (VisionReader), `proxy/proxy.go:1015-1127`
(VisionWriter), `proxy/proxy.go:1383-1460` (XtlsUnpadding)

**Duration**: 3-5 RTTs typically, exchanging small padding blocks.

**Execution model**:

VisionReader and VisionWriter run as concurrent goroutines. Each iteration:

**VisionReader** (`proxy.go:755`):
1. `Reader.ReadMultiBuffer()` — reads from the underlying connection
2. `XtlsUnpadding()` — parses the 5-byte header state machine
3. Command detection — cmd=0 loops, cmd=1/2 triggers state transition

**VisionWriter** (`proxy.go:1015`):
1. `XtlsFilterTls()` — inspects traffic for TLS patterns
2. `XtlsPadding()` — adds 5-byte header + random padding per buffer
3. `Writer.WriteMultiBuffer()` — writes through the underlying connection

**XtlsUnpadding state machine** (`proxy.go:1383-1460`):

Incremental parser. Tracks three counters: `remainingCommand` (5→0, parsing
header bytes), `remainingContent` (content bytes to copy), `remainingPadding`
(padding bytes to discard). When all three reach zero, the block is complete.
If `currentCommand == 0`, resets to parse the next block. If ≠ 0, sets all
counters to -1 (terminal state).

**When DeferredRustConn is active** (non-canonical path):

Each VisionReader iteration does:
1. `DeferredRustConn.Read()` → 1 CGO crossing (batched at 16KB, `tls.go:1119`)
2. `XtlsUnpadding` — pure Go, zero FFI
3. Command decision — pure Go

Each VisionWriter iteration does:
1. `XtlsPadding` — pure Go
2. `DeferredRustConn.Write()` → 1 CGO crossing (batched below 4KB, `tls.go:1197`)

**Minimum: 2 CGO crossings per padding record.** With N concurrent Vision
connections during padding: 2N pinned OS threads.

**Batching mitigations**:

- Read batching (`deferredReadBatched`, `tls.go:1119-1153`): 16KB internal
  buffer, single CGO crossing, caches remainder. Effective when multiple TLS
  records are queued; ineffective when waiting for peer response (common during
  padding exchange).
- Write batching (`tls.go:1197-1210`): Accumulates writes below 4KB before
  CGO crossing. Padding records are small enough that several often coalesce.

**Batching limits**: Helps throughput, not latency. The padding exchange is
request-response: read → parse → decide → respond → write → wait. The read
cache is often empty because the peer hasn't sent the next record yet.

**Rustification difficulty**: **Highest of all phases.** Moving padding to Rust
would require the XtlsUnpadding state machine, XtlsPadding, VisionSignal
channel equivalent, VisionWriter control flow, and `buf.MultiBuffer` management
all in Rust. This is moving the protocol layer, not the transport layer. The
Layer 2 attempt (271 functions) tried to bridge this gap and failed.

### Phase 2a: No-Detach Steady State (cmd=1)

**Code**: `proxy/proxy.go:829-837` (command detection),
`proxy/proxy.go:460-521` (`markVisionNoDetachObserved`)

**What happens**: VisionReader detects cmd=1 → sends VisionSignal → calls
`markVisionNoDetachObserved()` which sets `CopyGateForcedUserspace` on both
inbound and outbound. Vision padding stops. The connection enters stable
userspace streaming — data passes through without padding/unpadding.

**State transitions**:
- `VisionSemanticPhase` → `VisionSemanticPhaseNoDetach`
- `CopyGateState` → `CopyGateForcedUserspace`
- `CopyGateReason` → `CopyGateReasonVisionNoDetach`

**Acceleration surface**: Zero. By design. The connection keeps its TLS wrapper
(Go TLS or DeferredRustConn, depending on handshake path) and streams in
userspace indefinitely. No splice, no sockmap, no kTLS promotion.

**If DeferredRustConn is active**: Every read/write still crosses CGO. But
records are now application-sized (kilobytes, not the 50-200 byte padding
blocks), so CGO overhead amortizes well. The `rustls` inside DeferredRustConn
handles AES-GCM, which is comparable to Go's `crypto/tls` performance.

**kTLS gap (Patch 3 in improvement plan)**: In principle, kTLS could be enabled
after cmd=1 — the connection is in stable TLS streaming, exactly where kTLS
helps most. But `EnableKTLSOutcome()` consumes the deferred handle and is
potentially destructive (`failPromotion` closes the raw connection). Enabling
this safely is new feature work requiring 5 new tests and careful failure-path
handling. Correctly classified as "new feature work" by the external review.

### Phase 2b: Detach Transition (cmd=2)

**Code**: `proxy/proxy.go:838-898` (VisionReader detach path),
`proxy/proxy.go:378-410` (`startDetach`), `tls.go:1335-1385` (DrainAndDetach)

**What happens**: VisionReader detects cmd=2 → triggers detach. If
DeferredRustConn is active, `startDetach()` launches an async goroutine that
calls `dc.DrainAndDetach()`.

**The detach sequence**:

1. `startDetach(dc)` spawns a goroutine (`proxy.go:391`)
2. Goroutine calls `dc.DrainAndDetach()` which:
   - Holds `deferredMu` lock
   - Flushes pending writes via FFI
   - Calls `native.DeferredDrainAndDetach`
   - Stages drained plaintext bytes
   - Calls `native.DeferredFree`
   - Sets `detached.Store(true)`
3. VisionReader waits with adaptive timeout (`visionDetachWaitBudget()`,
   clamped to 500ms-1s)
4. On success: drained plaintext prepended to the read stream; VisionReader
   switches to raw socket reads
5. On timeout (`proxy.go:877-898`): stays on rustls path, sets
   `CopyGateForcedUserspace`

**Timeout budget** (`proxy.go:110-151`): EWMA-based, records past detach
durations and adjusts with 150ms slack. Clamped between 500ms and 1s.

**Historical bugs fixed here**:

- **Gap 13 (VisionWriter switch bug)**: Writer deferred its raw-socket switch
  while waiting for reader-side detach. Sent rustls-encrypted data after cmd=2.
  Fix: writer switches immediately via UnwrapRawConn.
- **Gap 15 (Blocking-fd write stall)**: `BlockingGuard` cleared `O_NONBLOCK`
  during detach. VisionWriter switched to raw socket while fd was blocking.
  Fix: `RestoreNonBlock()` FFI before VisionWriter switches.
- **Gap 9 (Cursor leftover data loss)**: `read()` silently discarded unconsumed
  cursor bytes after `read_tls`. Fix: `RecordReader::push_back()` saves
  leftover bytes.

**If DeferredRustConn is NOT active** (canonical deployment): cmd=2 simply
switches VisionReader to raw socket reads. No DrainAndDetach needed. No timeout
race. No async goroutine. The complexity of Phase 2b is entirely a consequence
of DeferredRustConn being active.

**Rustification difficulty**: Medium. DrainAndDetach is a contained transition
(one-shot, not iterative), but it has real edge cases as the bug history shows.
The timeout/fallback logic is Go-only and should remain so.

### Phase 3: Post-Detach Streaming (cmd=2 aftermath)

**Code**: `proxy/proxy.go:900-930` (post-detach read path)

**What happens**: VisionReader returns raw socket data. The copy loop evaluates
splice/sockmap eligibility. If both sockets are raw and kTLS-free:

- eBPF sockmap: theoretically possible, but blocked by `CanSpliceCopy` never
  transitioning to 1 (the uplink splice TODO at `proxy.go:301-302`)
- splice(2): possible for the response direction (`tc.ReadFrom()`)
- readV: the fallback

**Acceleration surface**: Splice in the response direction. Sockmap blocked by
the uplink splice TODO (cross-handler socket ownership between VisionReader and
freedom). This is the correct behavior — the analysis in
`ebpf-vision-analysis.md` confirmed sockmap would intercept client socket data
and starve VisionReader if registered bidirectionally.

**Rustification difficulty**: None. This is a raw socket phase. Rust is not
involved.

---

## III. The Acceleration Surface Map

| Phase | Records/sec | Record size | CGO crossings | kTLS | Splice | Sockmap | Acceleration ROI |
|-------|-------------|-------------|---------------|------|--------|---------|------------------|
| Handshake | N/A | N/A | 1 (one-shot) | N/A | N/A | N/A | **High** |
| Padding (cmd=0) | High | 50-200B | 2/record | No | No | No | **Negative** when via DeferredRustConn |
| No-detach (cmd=1) | Medium | KB-sized | 2/record | Gap (Patch 3) | No | No | Neutral; kTLS would improve |
| Detach (cmd=2 transition) | 1 | Variable | 1 (drain) | N/A | N/A | N/A | Low (one-shot) |
| Post-detach | Medium | KB-sized | 0 | No (raw) | Response dir | No | High for splice |

### Why Padding Is the Most Problematic Phase for Rustification

Ranked by difficulty:

1. **Padding (cmd=0)** — Hardest. Layer mismatch: protocol logic interleaved
   with every I/O operation. Tiny records make CGO overhead dominant. Bidirectional
   concurrent access requires three-lock design in `DeferredSession` (Gap 8 fix).
   This is where the archived branch spent 271 functions and failed.

2. **Detach transition (cmd=2)** — Medium. Contained but delicate one-shot
   operation. Multiple historical bugs (Gaps 9, 13, 15). Timeout/fallback
   complexity is significant.

3. **No-detach steady state (cmd=1)** — Low. Stable streaming. CGO cost
   amortizes over large records. The main question is whether kTLS promotion
   is safe here (Patch 3).

4. **Handshake** — Already done. Clean FFI boundary, one-shot, natural Rust
   territory.

5. **Post-detach streaming** — Not a Rust question. Raw socket, Go/kernel.

### The Fundamental Tension

Vision padding is **protocol-layer behavior** (parse 5-byte headers, decide
commands, apply padding) that must execute through a **transport-layer foreign
execution model** (DeferredRustConn).

When Go owns TLS (canonical deployment):

```
Go TLS Read → Go parse → Go decide → Go pad → Go TLS Write
```

When DeferredRustConn owns TLS:

```
Rust TLS Read (via CGO) → Go parse → Go decide → Go pad → Rust TLS Write (via CGO)
```

The protocol layer is sandwiched between two transport-layer FFI crossings on
every record. Go can't see into the TLS state; Rust can't see into the protocol
state. The boundary must be crossed twice per record, and each crossing has
non-trivial fixed cost (goroutine pin, stack switch, cgo_call overhead).

For application-sized records (KB+), this overhead is negligible. For 50-200
byte padding blocks over 3-5 RTTs, it dominates.

---

## IV. Copy Gate State Machine

The copy gate determines whether the copy loop can use splice, sockmap, or must
stay in userspace. It is the central arbiter of acceleration eligibility.

### States

| State | Meaning | Set by |
|-------|---------|--------|
| `CopyGateUnset` | No decision yet | Initial |
| `CopyGateEligible` | Splice/sockmap permitted | Post-detach, non-Vision flows |
| `CopyGatePendingDetach` | Waiting for Vision cmd=2 | Vision flow entry |
| `CopyGateForcedUserspace` | Must stay in userspace | Vision cmd=1, bypass, timeout |
| `CopyGateNotApplicable` | Transport can't splice | XHTTP (`splitConn`) |

### Transitions

```
                    ┌─ cmd=1 ──→ ForcedUserspace
                    │
Unset → PendingDetach ─┤
                    │
                    └─ cmd=2 ──→ Eligible (if detach succeeds)
                                │
                                └─ timeout → ForcedUserspace
```

Vision cmd=0 stays in `PendingDetach` — the gate hasn't decided yet because
more padding blocks may follow.

Non-Vision VLESS: `flowEmptyGate()` returns `CopyGateForcedUserspace` directly
(`inbound.go:818-826`). The env var `XRAY_FEATURE_FLOW_EMPTY_RAW_ACCEL=1` can
override this, but requires `IsRAWTransportWithoutSecurity(iConn)` which
DeferredRustConn doesn't satisfy.

XHTTP: `CopyGateNotApplicable` always (splitConn abstraction barrier).

### eBPF Sockmap Guard

Sockmap is correctly prevented for Vision via the copy gate. The primary guard
is `CanSpliceCopy` (the Go-side equivalent of copy gate state). For Vision:

- `inbound.CanSpliceCopy = 2` (PendingDetach equivalent)
- Never transitions to 1 (the uplink splice TODO at `proxy.go:301-302`)
- Post-detach crypto hint is `CryptoNone` (not `CryptoUserspaceTLS`)
- `CanSpliceCopy` is the **sole effective barrier** after Gap 8

Both directions use userspace readV copy after Vision detach.

---

## V. DeferredRustConn Lifecycle

For connections that DO use DeferredRustConn (non-canonical or PREFER_NATIVE),
the lifecycle is:

```
Rust REALITY handshake
    → DeferredRustConn wraps raw socket
    → Read/Write cross CGO boundary (Vision padding phase)
    → cmd=1: stay on DeferredRustConn (CopyGateForcedUserspace)
      cmd=2: DrainAndDetach → raw socket (CopyGateEligible)
    → Post-detach: Go owns raw socket
```

### Key Properties

- **Read batching** (`tls.go:1119`): 16KB internal buffer, single CGO crossing.
  Caches remainder for subsequent reads.
- **Write batching** (`tls.go:1197`): Accumulates below 4KB threshold.
- **DrainAndDetach** (`tls.go:1335`): Holds `deferredMu` → flush → FFI drain →
  stage drained bytes → `DeferredFree` → `detached.Store(true)`.
- **RestoreNonBlock** (Gap 15 fix): Restores `O_NONBLOCK` before VisionWriter
  switches to raw socket, while Rust reader/writer handle `EAGAIN` via `poll(2)`.
- **Three-lock design** (Gap 8 fix): `tls` lock (rustls state, brief), `reader`
  lock (socket reads, may block), `writer` lock (socket writes, brief). No
  method holds two locks.

### EnableKTLS Promotion

`EnableKTLSOutcome()` (`tls.go:1490-1620`):

1. Acquire deferred handle
2. Extract TLS secrets from rustls
3. Install kTLS keys via `setsockopt`
4. Sanity check via `MSG_PEEK`
5. On success: connection reads/writes go directly through kernel kTLS
6. On failure: `rollbackPromotionFailure` zeroes secrets; `failPromotion` may
   close the raw connection if the handle was consumed

**Destructive behavior**: `failPromotion` calls `closeAfterUnlock = true` when
`!handleRetained`. This means a failed promotion can close the underlying
connection. Not side-effect free. Protocol handlers must be prepared for this.

---

## VI. Track B1: The Road Not Taken

The archived improvement plan (`native-reality-improvement-plan-2026-03-13.md`,
§10a) identified an alternative approach: **Vision padding via Go TLS**.

The idea: After Rust completes the REALITY handshake, extract TLS session keys
via `dangerous_extract_secrets()` and construct a Go `tls.Conn` from those keys.
Vision padding then runs through Go TLS (no CGO crossings) while the handshake
benefit (Rust REALITY auth, semantic truth) is preserved.

**Estimated effort**: ~200 lines.
**Status**: Never built.
**Why**: The canonical deployment already avoids DeferredRustConn for Vision
via the AUTO loopback guard, making Track B1 unnecessary for the primary use
case. It remains a valid approach for non-canonical deployments that want Rust
REALITY auth without the DeferredRustConn execution model during Vision padding.
