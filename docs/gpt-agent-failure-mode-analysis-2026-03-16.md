# GPT Agent Failure Mode Analysis

**Date:** 2026-03-16
**Subject:** Behavioral analysis of GPT-5.4-xhigh operating as external development agent on Xray-core `perf` branch
**Scope:** Vision pipeline heuristic removal, Gemini stall regression, signal gate fix

---

## 1. Executive Summary

Over approximately two weeks of development on the Vision pipeline, the GPT agent exhibited a consistent failure mode: **serial symptom patching in the presence of a known architectural defect**. The agent correctly diagnosed the root cause (missing per-flow signal between VisionReader and the response loop) but deferred it through 6+ rounds of incremental fixes, each introducing additional Vision-specific complexity into a generic copy loop. When finally prompted to address the root cause, the agent bolted a signaling layer on top of the existing inference infrastructure rather than replacing it — producing more code, more functions, and more Vision-aware branching than the state it started from.

---

## 2. Observed Behavior Patterns

### 2.1 Diagnosis-Implementation Gap

The agent consistently produces accurate post-mortems. It correctly identifies root causes, failure modes, and the direction of the correct fix. But between diagnosis and implementation, it defaults to the smallest local patch that addresses the presenting symptom.

**Evidence:**

| Diagnosis (correct) | Implementation (local patch) |
|---------------------|------------------------------|
| "the remaining root cause is a missing explicit per-flow signal" | Added `atomic.Uint32` in a `sync.Map` instead of a channel |
| "we should not be building more of them [Vision heuristics]" | Added 6 new Vision functions, net +104 lines |
| "the right direction now is subtraction, not refinement" | Function count went from 43 to 49 |
| "the correct long-term move is probably to delete more of them" | No functions were deleted |

The agent knows what the right answer is, says it out loud, then does something else.

### 2.2 Fix-Then-Fix-The-Fix Chains

The agent produces sequential fix chains where each fix partially corrects the previous one:

- **Fix 1:** Required explicit post-detach truth before sockmap/splice retry (`shouldRetryVisionPostDetachTransition` rejects non-PostDetach flows).
- **Fix 2:** Fix 1 was too strict — command=2 flows with early userspace bytes were blocked. Loosened the condition: `userspaceBytes != 0 && semanticPhase != PostDetach`.

This pattern (tighten, discover over-tightened, loosen) is characteristic of local inference tuning rather than structural design. With a signal channel, neither fix would exist — the response loop would know command=2 arrived regardless of byte count.

### 2.3 Observability as Substitute for Repair

The agent treats instrumentation improvements as fixes:

- **Fix 3:** Widened breaker regression reporting to include non-zero-byte timeouts. This makes the breaker react to more failure modes but prevents none of them. The flows still die; the breaker just knows about it faster.
- **648 `command_continue_evidence`** telemetry events, **448 `response_wake`** events — infrastructure that monitors the problem rather than solving it.

### 2.4 Containment Over Correction

The agent invested ~676 lines in `native_policy.go` circuit breaker hardening:

- Threshold-1 regression detection
- Threshold-2 serialized recovery
- Exponential backoff on repeated opens
- In-flight sibling suppression
- Idle re-entry probes

All well-engineered. All exist to quarantine a failure mode (unresolved command=0 flows timing out) that shouldn't happen if the copy loop could receive a direct signal from VisionReader.

### 2.5 Reluctance to Change Concurrency Primitives

The agent repeatedly chose `sync.Map` + `atomic` + `SetReadDeadline` over channels. This pattern appears across the codebase:

- `pipelineVisionResponseGateByConn` — sync.Map of `*visionResponseGate`
- `pipelineVisionUplinkUnixByConn` — sync.Map of timestamps
- `pipelineVisionRawUnwrapUnixByConn` — sync.Map of timestamps

Each requires manual registration, lookup, and cleanup. A per-flow channel (created with the flow, garbage-collected with the flow) eliminates all three maps and their lifecycle management.

The `SetReadDeadline(time.Now())` wake hack is the clearest symptom: the agent uses socket deadlines as an IPC mechanism because it won't introduce a `select` loop with a channel.

---

## 3. Architecture-Patch Mismatch: Detailed Analysis

### 3.1 The Architectural Problem

VisionReader (running in the uplink goroutine) discovers commands. The response loop (running in the response goroutine) needs to act on them. The two goroutines share no direct communication channel.

**Current communication path:**
```
VisionReader
  → stores signal in atomic.Uint32
    → (optionally) calls SetReadDeadline(time.Now()) on response socket
      → response loop's readV returns with timeout error
        → response loop polls effectiveVisionResponseSignal()
          → merges atomic signal with committedVisionSemanticPhase()
            → runs shouldRetryVisionPostDetachTransition() (8 params)
              → runs applyVisionStableUserspaceGateDecision()
                → decides what to do
```

**Correct communication path:**
```
VisionReader
  → sends command to channel
    → response loop receives from channel in select
      → acts on command
```

### 3.2 What the Agent Built vs What Was Needed

| Aspect | Agent's implementation | Architectural solution |
|--------|----------------------|----------------------|
| Signal storage | `atomic.Uint32` in `sync.Map` | `chan visionResponseSignal` on flow struct |
| Signal delivery | Polled on timeout via `effectiveVisionResponseSignal()` | Received via `select` |
| Wake mechanism | `SetReadDeadline(time.Now())` socket hack | Channel send unblocks `select` |
| State merger | `effectiveVisionResponseSignal()` merges atomic + semantic phase | Channel is the single source of truth |
| Lifecycle | Manual register/unregister in sync.Map | Channel created with flow, GC'd with flow |
| Vision awareness in copy loop | 4 Vision-specific decision points in error handler | 1 `select` case, no Vision vocabulary |
| Function count delta | +6 new Vision functions | -18 Vision functions (wake/timestamp/inference layer removed) |
| Line count delta | +104 lines | Estimated -400 lines (sync.Maps, timestamp infra, inference helpers) |

### 3.3 The Signal Gate: Detailed Critique

The agent's `visionResponseGate` (lines 121-124):

```go
type visionResponseGate struct {
    wakeTarget gonet.Conn
    signal     atomic.Uint32
}
```

This struct is stored in a global `sync.Map` keyed by unwrapped `*DeferredRustConn`. Problems:

1. **Global mutable state for per-flow data.** Every signal read requires a sync.Map lookup + pointer unwrap + atomic load. A field on the flow struct is a direct access.

2. **Two sources of truth.** `effectiveVisionResponseSignal()` (line 2991) merges the atomic signal with `committedVisionSemanticPhase()` — which reads `VisionSemanticPhase()` from both inbound and all outbounds. The merge function exists because the signal store was added alongside the existing semantic phase store instead of replacing it.

3. **Manual lifecycle.** `registerVisionResponseWakeTarget` must be called at flow start; `unregisterVisionResponseWakeTarget` at flow end; `prepareVisionStableUserspaceRead` when transitioning to stable userspace. A channel has no lifecycle to manage.

4. **The CAS loop is unnecessary.** `storeVisionResponseSignal` (lines 774-786) implements a CAS loop for monotonic advancement. A buffered channel of size 1 with latest-wins semantics achieves the same thing.

### 3.4 The Test Reveals the Fragmentation

The integration test for command=2 arriving after uplink completion (lines 1606-1616):

```go
time.AfterFunc(500*time.Millisecond, func() {
    ObserveVisionUplinkComplete(ctx, inbound, outbound)
})
time.AfterFunc(700*time.Millisecond, func() {
    markVisionPostDetachObserved(ctx, outbound)
    markDeferredRustConnDetachedForTest(writerConn)
    storeVisionResponseSignal(ctx, writerConn, visionResponseSignalPostDetach, "test-command-2", true)
})
```

Simulating a single event (command=2 arrives) requires 3 function calls updating 3 separate state stores (semantic phase, deferred conn detach flag, atomic signal). With a channel, it would be:

```go
signalCh <- VisionCommandDetach
```

The test is documenting the state fragmentation.

---

## 4. Failure Mode Taxonomy

### 4.1 Primary: Incremental Descent

The agent starts with a correct high-level diagnosis, then descends into implementation by addressing the nearest concrete symptom. Each fix is locally correct but globally accumulative. The codebase grows monotonically because fixes are additive (new checks, new functions, new state) rather than substitutive (new mechanism replaces old mechanism).

**Trigger:** Any runtime failure or log anomaly.
**Response:** Identify the specific code path, add a guard/check/signal at that point.
**Outcome:** The specific failure stops; total complexity increases; the next failure is harder to diagnose because it interacts with more guards.

### 4.2 Secondary: Vocabulary Inflation

Each round of fixes introduces new domain vocabulary into the generic copy loop:

- Round 1: `CopyGatePendingDetach`, `VisionSemanticPhase`, `CopyGateReason`
- Round 2: `visionControlUserspaceCompatible`, `visionOpaqueControlCompatEligible` (since removed)
- Round 3: `userspacePhasePreDetach`, `userspacePhaseNoDetach`, `userspacePhasePostDetach`, `userspacePhaseStreaming`
- Round 4: `visionResponseSignal`, `visionResponseGate`, `effectiveVisionResponseSignal`, `visionPreDetachReadTimeout`

The copy loop now speaks Vision fluently. A protocol-agnostic copy loop should speak zero Vision.

### 4.3 Tertiary: Containment Bias

When a failure class resists local patching, the agent builds containment infrastructure (circuit breakers, retry suppressors, regression reporters) rather than fixing the root cause. This is the "if you can't fix it, manage it" pattern. Containment is appropriate for failures at system boundaries (external services, hardware faults). It is inappropriate for failures in internal control flow where the fix is a different concurrency primitive.

---

## 5. Quantitative Summary

### Before heuristic removal (perf branch, earlier state)
- 53 Vision-specific functions in proxy.go
- 3,620 lines in proxy.go
- 7 userspace phase states
- 5 sync.Maps for Vision per-connection state
- Grace windows: 750ms first-byte, 350ms uplink-complete, 250ms quiet

### After heuristic removal + 6 fixes + signal gate (current state)
- 49 Vision-specific functions in proxy.go
- 3,281 lines in proxy.go
- 4 userspace phase states
- 5 sync.Maps for Vision per-connection state (1 repurposed)
- Grace windows removed
- Signal gate added (atomic.Uint32 in sync.Map)
- 676 lines of circuit breaker in native_policy.go

### After architectural fix (target state)
- ~25 Vision-specific functions in proxy.go (protocol truth only)
- ~2,800 lines in proxy.go (estimated)
- 2 response-loop states: waiting-for-signal, active
- 2 sync.Maps for Vision per-connection state (timestamp telemetry only)
- 1 channel per flow, created at flow start, GC'd at flow end
- Response loop Vision switch replaced by `select` case
- Circuit breaker remains for genuine transport failures, not internal signaling races

---

## 6. Key Takeaway

The agent is a skilled diagnostician and a disciplined incrementalist. It will never produce a catastrophic regression because it changes the minimum necessary code to address each symptom. But it will never produce a simplification either, because its working unit is the individual code path, not the system structure. Left to operate indefinitely, it will converge on a codebase where every failure mode has a dedicated guard, every guard has a dedicated test, and the aggregate complexity makes the next failure mode harder to diagnose — which triggers the next round of guards.

The corrective is to constrain the agent to work from architectural plans that specify both what to build AND what to delete, with deletion targets as acceptance criteria.
