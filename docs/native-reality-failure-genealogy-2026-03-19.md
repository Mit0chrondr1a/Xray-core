# Native REALITY Failure Genealogy — 2026-03-19

## Purpose

This document traces how the native REALITY integration attempt — a plan drawn
after serious analysis, with sound architectural principles — failed in
execution. It is not a hindsight critique but a genealogy: the sequence of
structurally reasonable decisions that compounded into a 271-function, 16,000-line
compensation system delivering zero acceleration in the canonical deployment.

The audience is anyone considering deep Rust-into-Go integration for a protocol
pipeline. The failure mode is general, not specific to this codebase.

Related documents:

- [native-reality-rust-handshake-boundary-2026-03-14.md](native-reality-rust-handshake-boundary-2026-03-14.md) — the boundary lesson
- [native-reality-improvement-plan-2026-03-13.md](native-reality-improvement-plan-2026-03-13.md) — the original analysis
- [native-reality-layer1-archive-2026-03-14.md](native-reality-layer1-archive-2026-03-14.md) — the archived code
- [acceleration-pipeline-improvement-plan-2026-03-17.md](acceleration-pipeline-improvement-plan-2026-03-17.md) — the current plan

Snapshot: `perf` branch at `f5a28e50`, 2026-03-19.

---

## I. The Plan That Failed

### The Original Division of Labor

The plan was:

> Rust owns semantics, Go handles pipeline.

Concretely:

- **Rust** performs the REALITY handshake (rustls), owns the TLS session via
  `DeferredRustConn`, and exports semantic events (auth outcome, TLS version,
  cipher) via FFI.
- **Go** consumes those events and runs the Vision padding protocol, copy-gate
  state machine, splice/sockmap decisions, and protocol-layer logic.

The architecture was clear about what each language owned. The handshake boundary
was sound. The deferred kTLS design was correct. Multiple critical bugs were
identified and fixed (Gaps 8-15). The plan passed a conditional production
review on 2026-02-27.

### The Canonical Deployment

All analysis is grounded in:

```
nginx SNI shunter → loopback TCP → REALITY → Vision/TCP → fallback → XHTTP
```

In this deployment:

- The AUTO policy guard (`native_policy.go:649`) skips Rust REALITY on loopback.
- All REALITY handshakes use Go's `reality.Server()`.
- Vision sees a Go REALITY connection, not `DeferredRustConn`.
- The DeferredRustConn execution model is never activated for Vision traffic.

**Total Rust REALITY acceleration in the canonical Vision pipeline: 0%.**

The only Rust acceleration is on direct XHTTP connections that bypass the VLESS
fallback path — and that was already shipped on the `rust` branch HEAD before
the Layer 2 attempt began.

---

## II. Three Inflection Points

### Inflection 1: The Lossy Information Channel

**Decision**: Go polls Rust for semantic events at the top of the copy loop.

**Implementation**: `DeferredPollSemanticEvent` — a Go function that calls into
Rust FFI at the start of each copy iteration, asking "has anything semantically
interesting happened?"

**Why it seemed correct**: The plan said "Rust owns semantics, Go handles
pipeline." Polling is the natural way for a pipeline consumer (Go) to ask a
semantic producer (Rust) for state changes.

**What went wrong**: The poll cannot fire while Go is blocked inside
`DeferredRead()`. During Vision padding, VisionReader calls DeferredRustConn.Read(),
which blocks in a CGO call until data arrives. The semantic poll sits at the top
of the copy loop, ABOVE the read. So the sequence is:

```
poll (Rust says nothing new) → read (blocks for RTT) → poll → read → ...
```

Rust might detect something semantically important (cipher negotiated, TLS
version confirmed) between polls, but Go won't see it until the next read
completes. For a protocol exchange with 3-5 RTTs of small records, this
means semantic events arrive 1-2 records late.

**Compensation attempt**: Dedup guards make events write-once — if Go misses the
window, the event is still there next poll. But this creates a different problem:
Go's protocol logic now operates on stale state for 1-2 records. The padding
decisions made during those records may be suboptimal or wrong.

**Structural lesson**: Polling across an FFI boundary is inherently lossy when
the consumer blocks on I/O from the same producer. The information channel has
a fundamental timing gap that cannot be closed without moving the consumer into
the producer's runtime — which defeats the purpose of the language boundary.

### Inflection 2: Measurement-to-Control Boundary Violation

**Decision**: The Layer 1 measurement infrastructure (174 functions, +18 lines to
proxy.go) was extended to drive control decisions in the copy loop.

**What Layer 1 was**: A measurement and semantic vocabulary system. It added:

- `VisionSemanticPhase` — an enum tracking where in the Vision protocol the
  connection currently is (padding, no-detach, post-detach)
- Semantic bridge taxonomy — correlating Vision transitions with transport events
- Probe/oracle terminology — a consistent vocabulary for runtime observations

Layer 1 was architecturally sound. An external review confirmed this. It added
exactly 18 lines to `proxy.go` — measurement annotations, not control logic.

**What Layer 2 was**: The decision to have Layer 1's measurements drive
response-loop behavior. Layer 2 added:

- 95 additional functions (35 of which were heuristic compensation)
- 9 response-loop phases
- 4 timeout constants
- `sync.Map` wake signaling between goroutines
- Decision functions that consumed semantic events to adjust copy-gate states,
  splice eligibility, and Vision command handling

**Why it seemed correct**: If you have accurate measurements (Layer 1), using
them to improve decisions (Layer 2) is the obvious next step. The external review
even noted that Layer 1's vocabulary was well-designed for this purpose.

**What went wrong**: The measurements were accurate descriptions of what had
already happened. Using them for real-time control requires that the measurements
arrive BEFORE the control decision. But due to Inflection 1 (the lossy
information channel), measurements arrived late. Layer 2 compensated by adding
prediction heuristics — "if we've seen 3 cmd=0 blocks, the next one is probably
cmd=0 too." These heuristics worked for common cases but introduced new failure
modes for edge cases (early cmd=1, split records, timeout races).

**The compensation spiral**: Each heuristic failure required another heuristic to
handle the edge case. 35 of the 95 Layer 2 functions were compensating for
other Layer 2 functions. The system became a heuristic stack where each layer
corrected the previous layer's approximations.

**Structural lesson**: Measurement infrastructure should measure. When
measurements become control inputs, the latency and accuracy requirements change
fundamentally. A measurement that's "accurate within one record" is fine for
telemetry but may be fatally wrong for a protocol-layer control decision.

### Inflection 3: Unbounded State Machine Compensation

**Decision**: Rather than questioning whether DeferredRustConn should be active
during Vision padding, the system added increasingly sophisticated state machines
to manage the consequences.

**The state machines**:

- `VisionSemanticPhase` (4 states) — tracks protocol phase
- `CopyGateState` (5 states) — tracks splice/sockmap eligibility
- `copyLoopPhase` (4 states) — tracks the copy loop's internal state
- `visionDetachFuture` (3 states) — tracks the async detach operation
- Response-loop phase machine (9 states) — orchestrates the above

Each state machine was individually correct. The interactions between them were
not always predictable.

**Example — the VisionWriter switch bug (Gap 13)**: VisionWriter deferred its
raw-socket switch when DeferredRustConn was present but not yet detached. The
writer waited for the reader to complete DrainAndDetach before switching. But
the writer had already sent cmd=2, telling the peer "I've switched to raw." The
peer started reading raw bytes while the writer was still sending through rustls.
Result: garbled data.

The fix was simple: remove the deferral, switch immediately. But the deferral
was there because another state machine (the copy-gate machine) expected a
specific transition order. Removing the deferral meant adjusting the copy-gate
machine, which meant adjusting the splice eligibility logic. Each "simple fix"
propagated through multiple state machines.

**The root cause was never addressed**: DeferredRustConn should not have been
active during Vision padding. All the state machines were managing consequences
of a decision that should have been prevented by policy. The AUTO loopback guard
does exactly this — and it was present from the start. The Layer 2 system was
optimizing a path that the policy layer already avoided.

**Structural lesson**: When you find yourself building state machines to
compensate for a design decision, question the decision. The number of
compensation mechanisms is a direct measure of the original decision's
mismatch with the problem domain.

---

## III. The Numbers

### Layer 1 (Measurement) — Architecturally Sound

| Metric | Value |
|--------|-------|
| Functions added | 174 |
| Lines added to proxy.go | 18 |
| New files | 0 (annotations in existing files) |
| External review verdict | Sound |
| Production impact | None (measurement-only) |
| Archived | `archive/native-reality-layer1-2026-03-14` at `060433e0` |

### Layer 2 (Response-Loop Compensation) — Structurally Infeasible

| Metric | Value |
|--------|-------|
| Functions added | 95 (35 heuristic compensation) |
| Total function count | 271 (Layer 1 + Layer 2) |
| Total lines | ~16,000 |
| UX regressions | Severe (stalls, garbled data, timeout races) |
| Canonical deployment acceleration | 0% |
| Archived | Working tree only; never committed to `perf` |

### The Retreat

| Metric | Value |
|--------|-------|
| Archive branch | `archive/native-reality-layer1-2026-03-14` |
| Retreat commit | `c3eb221e` on `perf` |
| Net delta vs archive | +794 / -7,847 lines |
| Retained | VisionSemanticPhase, cmd=1 semantic/local split, cmd=2 post-detach |
| Dropped | `vision_transition.go` (3,045 lines), probe consumers, deferred lifecycle |

---

## IV. Why "Rust Owns Semantics, Go Handles Pipeline" Failed

The plan failed not because the division was wrong in principle, but because it
underestimated the coupling between semantics and pipeline in the Vision protocol.

In a protocol like XHTTP, "semantics" and "pipeline" are cleanly separable: the
TLS handshake produces a session, the HTTP layer consumes it, and data flows
through. Rust can own the handshake, Go can run HTTP, and the boundary is a
connection object with well-defined properties.

In Vision, "semantics" and "pipeline" are interleaved on every record during
the padding phase:

1. **Read** a TLS record (transport)
2. **Parse** the 5-byte Vision header (protocol semantics)
3. **Decide** what command this is (protocol semantics)
4. **Act** on the command — loop, signal, or detach (pipeline control)
5. **Write** the response with padding (transport + protocol semantics)

Steps 2-4 depend on the result of step 1. Step 5 depends on steps 2-4. If step
1 crosses an FFI boundary, steps 2-4 operate on data that arrived through that
boundary — with the latency and scheduling consequences that entails. If step 5
also crosses the boundary, the protocol loop has two FFI crossings per record.

The fundamental tension: **Vision padding is protocol-layer behavior that must
execute through a transport-layer foreign execution model.** "Rust owns
semantics" means Rust owns the TLS transport. "Go handles pipeline" means Go
runs the Vision protocol. But Vision's protocol logic is inseparable from its
transport I/O during the padding phase.

This is not a Go or Rust problem. It is a layer mismatch problem. Any attempt
to split an interleaved protocol across two language runtimes will encounter
the same coupling.

---

## V. The Correct Boundary

The boundary lesson, empirically derived from the 271-function failure:

| Layer | Owner | Rationale |
|-------|-------|-----------|
| REALITY handshake | Rust | Contained, one-shot, natural FFI boundary |
| Transport truth (TLS version, cipher, auth) | Rust | Available at handshake completion |
| Non-Vision acceleration (kTLS, eBPF) | Rust/Kernel | No protocol-layer interleaving |
| Post-detach support (cmd=2 aftermath) | Raw socket | Rust not involved |
| Vision padding (cmd=0) | Go | Protocol-layer logic, tightly coupled to I/O |
| Vision no-detach (cmd=1) | Go | Stable userspace streaming |
| Parser-boundary commits | Go | Protocol semantics, not transport semantics |

The `perf` branch HEAD (`f5a28e50`) implements this boundary. The improvement
plan (`acceleration-pipeline-improvement-plan-2026-03-17.md`) proposes three
patches that extend acceleration without crossing it.

---

## VI. Generalized Failure Modes

These failure modes are not specific to Xray-core. They apply to any project
grafting a compiled FFI layer into a managed-runtime protocol pipeline.

### 1. The Amortization Illusion

CGO crossing overhead (~100-200ns per call) is negligible for large records
(16KB+ application data) but dominates for small records (50-200 byte padding
blocks). Acceleration ROI is inversely proportional to the protocol's record
size during the critical phase. If the critical phase uses small records, the
FFI boundary cost exceeds the acceleration benefit.

### 2. The Compensation Cascade

When the original design decision introduces a mismatch, each fix creates a new
edge case that requires another fix. The total system complexity grows
super-linearly. The inflection point is recognizable: when compensation functions
start compensating for other compensation functions.

### 3. The Measurement-to-Control Trap

Measurement infrastructure designed for observability has different latency
requirements than control infrastructure. Repurposing measurement as control
input without addressing the latency gap creates a prediction problem that
produces heuristic compensation — see failure mode #2.

### 4. The Canonical Deployment Blind Spot

A feature optimizing a non-canonical path can grow to arbitrary complexity
because its cost is never measured against the deployment it doesn't help.
The canonical deployment already avoids the problem (via the AUTO loopback
guard). All 271 functions optimized a path that production traffic never takes.

---

## VII. The Lesson in One Sentence

> When you find yourself building a state machine to compensate for a design
> decision, the design decision is the bug.
