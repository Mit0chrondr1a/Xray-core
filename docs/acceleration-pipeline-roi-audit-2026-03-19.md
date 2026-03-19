# Acceleration Pipeline ROI Audit — 2026-03-19

## Purpose

This document audits every acceleration integration point along the canonical
deployment pipeline, assessing ROI soundness, infrastructure weight, and
potential miscalculations analogous to the Vision-padding-into-Rust failure.

The audit was prompted by an external GPT-5.4-xhigh session that attempted to
discover "overlooked acceleration integration points" and produced
high-dimensional analysis of structurally infeasible paths. This document
provides the sober counterpart: what the pipeline actually does, what it could
do, and where the investment-to-payoff ratio is miscalibrated.

Snapshot: `perf` branch at `f5a28e50`, 2026-03-19.

Related documents:

- [acceleration-pipeline-improvement-plan-2026-03-17.md](acceleration-pipeline-improvement-plan-2026-03-17.md)
- [native-reality-failure-genealogy-2026-03-19.md](native-reality-failure-genealogy-2026-03-19.md)
- [vision-pipeline-walkthrough-2026-03-19.md](vision-pipeline-walkthrough-2026-03-19.md)

---

## I. Pipeline Stage Audit

### Stage 1: TCP Accept → Handshake

**TCP REALITY** (`hub.go:374-500`):

- Rust handshake via `doRustRealityDeferredFn` — one-shot FFI call
- Controlled by AUTO policy with loopback guard (`native_policy.go:649`)
- Circuit breaker protects against systematic handshake failures
- **ROI: Sound.** Contained operation, clear boundary, appropriate safeguards.

**TCP TLS** (`hub.go:349-373`):

- Go `tls.Server()` + `HandshakeContext()`
- No Rust involvement in the handshake
- kTLS decision deferred to protocol handler (correct — Vision needs to decide)
- **ROI: Sound.** Minimal, correct.

**XHTTP kTLSListener** (`splithttp/hub.go:509-565`):

- `RustServerWithTimeout()` → kTLS → `KTLSPlaintextConn` → h2c
- 55 lines. Highest payoff integration point — XHTTP keeps outer TLS active for
  the full session, so kTLS amortizes across megabytes.
- Retry loop for per-connection handshake failures; exponential backoff.
- **ROI: Excellent.** Minimal code, maximum acceleration surface.

**XHTTP kREALITYListener** (`splithttp/hub.go:570-1178`):

- `processConn()` (~170 lines) duplicates TCP hub.go's REALITY cascade:
  extract fd → Rust deferred → wrap DeferredRustConn → EnableKTLSOutcome →
  handle 6 failure modes → fallback to Go REALITY
- Separate set of 40+ atomic telemetry counters
- No circuit breaker (TCP has one, XHTTP doesn't share it)
- **ROI: Correct behavior, duplicated infrastructure.** See §II.

### Stage 2: Native Policy and Circuit Breaker

**native_policy.go** (675 lines):

- Policy mode evaluation (AUTO, PREFER_NATIVE, FORCE_NATIVE, DISABLE_NATIVE)
- Circuit breaker state machine (~180 lines): closed → open → half-open
- Scope keying by inbound tag + security + transport
- Runtime regression threshold = 1 (deliberate, `native_policy.go:487`)
- Runtime recovery threshold = 2 half-open successes (`native_policy.go:511`)
- Handshake success alone doesn't close a runtime-opened breaker (`native_policy.go:432-448`)
- Idle re-entry probe after `4 * cooldown` or `2min` (whichever is larger)

**ROI assessment**: The circuit breaker is important for production safety. The
policy evaluation is necessary. The concern is not that this code exists but
that it is 675 lines supporting what amounts to a per-connection boolean decision:
"attempt Rust handshake: yes/no."

### Stage 3: Protocol Detection (VLESS Inbound)

**Vision flow** (`inbound.go:675-698`):

- Detects DeferredRustConn presence → sets `deferredVisionPath = true`
- Increases `NumberOfPacketToFilter` from 16 to 32
- Applies `applyVisionExecutionGate`
- **ROI: Correct.** Minimal code, appropriate lifecycle setup.

**Non-Vision VLESS (flow=="")** (`inbound.go:702-732`):

- DeferredRustConn → `EnableKTLSOutcome()` — kTLS installs successfully
- Go TLS → `HandshakeAndEnableKTLS()` — kTLS installs successfully
- But `flowEmptyGate()` (`inbound.go:818-826`) returns `CopyGateForcedUserspace`
- `IsRAWTransportWithoutSecurity()` (`proxy.go:2830-2836`) checks for
  `*net.TCPConn`, `*proxyproto.Conn`, `*internet.UnixConnWrapper` — DeferredRustConn
  doesn't match
- **ROI: Partially realized.** See §III Finding 2.

### Stage 4: Copy Loop

**proxy.go** (2,836 lines):

The copy loop is the data-plane engine. Its complexity is inherent to the problem:
Vision state machine, copy-gate evaluation, splice/sockmap dispatch, runtime
regression reporting, DNS control-plane guards, XUDP integration.

Within this, ~200 lines (`proxy.go:530-696`) exist to feed runtime health
signals from the copy loop back to the handshake-layer circuit breaker. This is
the runtime regression/recovery reporting system: `shouldReportNativeDeferredRuntimeRegression`,
`maybeReportNativeDeferredRuntimeRecovery`, `shouldReportFallbackNativeRuntimeRecovery`, etc.

**ROI: Correct but heavy.** The reporting system is a bidirectional feedback
loop between the copy loop (consumer) and the handshake policy (producer). It
exists because the circuit breaker can't know whether a DeferredRustConn
connection will succeed until the copy loop runs. This is sound engineering, but
it means the copy loop carries permanent observability weight for the handshake
layer.

### Stage 5: Outbound Dialer

**TCP dialer** (`tcp/dialer.go:87-199`):

- Three-way split: fingerprint → uTLS, native eligible && !Vision && !DNS →
  Rust, else → Go TLS
- Vision flow gate (`dialer.go:144`): skips Rust for Vision flows
- DNS control-plane gate (`dialer.go:145`): skips Rust for short-lived DNS
- **ROI: Sound.** Clean dispatch, correct gates, minimal code.

**XHTTP client dialer** (`splithttp/dialer.go:109-156`):

- Three-way: fingerprint → uTLS, native available → `RustClientWithTimeout`,
  else → `HandshakeAndEnableKTLS`
- No Vision gates needed (XHTTP doesn't do Vision)
- **ROI: Sound.**

### Stage 6: eBPF Sockmap

**sockmap.go** (`transport/internet/ebpf/sockmap.go`):

- Manages sockmap-based zero-copy TCP forwarding
- Rust/Aya loader preferred, Go-native fallback
- LRU eviction for SOCKHASH entries
- Contention detection and splice fallback

**Who benefits**:
- Non-Vision + raw TCP + both directions eligible → very narrow
- Vision excluded (CanSpliceCopy never transitions)
- XHTTP excluded (splitConn abstraction barrier)
- kTLS connections may hit kernel SOCKHASH incompatibility

**ROI: Correct for its niche.** The niche is just smaller than the infrastructure
might suggest. Primarily benefits direct TCP connections without Vision or XHTTP
framing.

### Stage 7: XHTTP Transport

**splitConn abstraction**: XHTTP proxy sees HTTP body streams (`splitConn`),
not raw sockets. This means:

- `CopyGateNotApplicable` always (`splithttp/hub.go:37-47`)
- No splice (no raw fd)
- No sockmap (no raw fd)
- No kernel-level forwarding

**XHTTP's only acceleration vector is TLS-layer**: kTLS on the outer connection.
This is exactly what kTLSListener and kREALITYListener deliver. The extensive
sockmap/splice/copy-gate infrastructure in `pipeline/`, `ebpf/`, and `proxy.go`
is completely irrelevant to XHTTP.

**ROI: Correct by design.** The HTTP abstraction boundary is fundamental. But
it means a significant portion of the acceleration infrastructure (sockmap,
splice dispatch, copy-gate state machine) has zero payoff for XHTTP — the
transport that benefits most from kTLS.

---

## II. Finding 1: Telemetry Infrastructure Duplication (High)

### The Problem

TCP and XHTTP perform the same REALITY handshake cascade with completely
separate telemetry:

**TCP hub.go atomic counters** (lines 48-89):
```
tcpRealityMarkerRustAttempt, tcpRealityMarkerRustSuccess,
tcpRealityMarkerRustPathIneligible, tcpRealityMarkerNativeSkipPolicy,
tcpRealityMarkerNativeSkipBreaker, tcpRealityMarkerRustFDExtractFailed,
tcpRealityMarkerRustAuthFallback, tcpRealityMarkerRustPeekTimeoutFallback,
tcpRealityMarkerRustWrapFailed, tcpRealityMarkerRustHandshakeFailed,
tcpRealityMarkerRustDurationNanosTotal, tcpRealityMarkerRustDurationSamples,
tcpRealityMarkerGoFallbackAttempt, tcpRealityMarkerGoFallbackSuccess,
tcpRealityMarkerGoFallbackFailed, tcpRealityMarkerGoFallbackNanosTotal,
tcpRealityMarkerGoFallbackSamples
```
Plus `Last`-prefixed duplicates for delta snapshots = ~34 atomic variables.

**XHTTP hub.go atomic counters** (lines 591-641):
```
xhttpRealityMarkerRustAttempt, xhttpRealityMarkerRustSuccess,
xhttpRealityMarkerRustFDExtractFailed, xhttpRealityMarkerRustAuthFallback,
xhttpRealityMarkerRustPeekTimeoutFallback, xhttpRealityMarkerRustWrapFailed,
xhttpRealityMarkerRustHandshakeFailed, xhttpRealityMarkerRustDurationNanosTotal,
xhttpRealityMarkerRustDurationSamples, xhttpRealityMarkerKTLSPromoteAttempt,
xhttpRealityMarkerKTLSPromoteSuccess, xhttpRealityMarkerKTLSPromoteFailed,
xhttpRealityMarkerGoFallbackAttempt, xhttpRealityMarkerGoFallbackSuccess,
xhttpRealityMarkerGoFallbackFailed, xhttpRealityMarkerGoFallbackNanosTotal,
xhttpRealityMarkerGoFallbackSamples, xhttpDecisionRustKTLS,
xhttpDecisionRustUserspace, xhttpDecisionGoFallback, xhttpDecisionDrop
```
Plus `Last`-prefixed duplicates = ~42 atomic variables.

**Total**: ~76 atomic counter variables tracking the same category of events
(handshake attempt → outcome → fallback) in parallel code paths.

Each path has its own snapshot logging function (~70 lines each):
`maybeLogTCPRealityHandoverMarkers` and `maybeLogXHTTPRealityHandoverMarkers`.

### The Consequence

The duplication is not a correctness problem — both paths work. It is an
**infrastructure gravity** problem. When the next person adds a new handshake
metric (e.g., "time from fd extraction to handshake start"), they must add it
in both places, with both snapshot pairs, in both logging functions. This
doubles the maintenance cost and creates divergence risk.

More insidiously, the sheer volume of telemetry creates the impression that the
handshake decision is more complex than it is. A reader seeing 76 atomic counters
may conclude that there are subtle failure modes requiring this granularity. In
practice, the handshake decision is: "try Rust, succeeded? done. failed?
fallback to Go or close." The telemetry schema was designed for diagnosing early
deployment issues and has not been pruned since.

### The Fix (Not Proposed Here)

A shared `realityHandshakeRecorder` type parameterized by listener tag would
eliminate the duplication. Both TCP and XHTTP would instantiate it with their
scope tag and call the same methods. Estimated delta: -120 lines, -38 atomic
variables.

This is an ergonomics improvement, not an acceleration improvement. It does not
change any data-plane behavior.

---

## III. Finding 2: Non-Vision VLESS kTLS Without Copy-Path Benefit (Medium)

### The Situation

For non-Vision VLESS connections (flow=="") arriving on DeferredRustConn:

1. `EnableKTLSOutcome()` succeeds (`inbound.go:712-720`) — kernel handles
   AES-GCM encrypt/decrypt
2. `flowEmptyGate()` returns `CopyGateForcedUserspace` (`inbound.go:818-826`)
   — copy loop must use userspace readV, not splice or sockmap
3. `IsRAWTransportWithoutSecurity()` (`proxy.go:2830-2836`) checks for raw
   socket types — DeferredRustConn doesn't match

### What This Means

kTLS is installed. The kernel does crypto. But the Go copy loop still does
`read()` → buffer → `write()` for every chunk of data. This is still a net
benefit — AES-GCM in kernel is faster and uses fewer CPU cycles than Go's
`crypto/tls` — but the full potential (kTLS + splice for zero-copy) is
unrealized.

The env var `XRAY_FEATURE_FLOW_EMPTY_RAW_ACCEL=1` was added to gate splice
enablement, but it requires `IsRAWTransportWithoutSecurity(iConn)`. After kTLS
promotion, DeferredRustConn's deferred handle is consumed and the underlying
connection is a raw TCP socket with kTLS keys installed. The type assertion
checks the Go wrapper type, not the socket's actual state.

### ROI Assessment

**kTLS alone** (current state): Real CPU savings. AES-GCM offloaded to kernel.
Worthwhile even without splice.

**kTLS + splice** (potential): Would eliminate the userspace copy entirely.
Requires either: (a) DeferredRustConn to satisfy `IsRAWTransportWithoutSecurity`
after kTLS promotion, or (b) a kTLS-specific type assertion in
`fallbackRawHandoffEligible`.

This is the improvement plan's Patch 1 territory (loopback guard removal) plus
the type-assertion gap. Correctly gated behind an env var. Not a miscalculation
— a known incomplete feature.

---

## IV. Finding 3: Infrastructure-to-Acceleration Ratio (Structural)

### The Ratio

**Acceleration code** (actual data-plane work):

| Component | Lines | What it does |
|-----------|-------|--------------|
| Rust handshake FFI call + wrap | ~50 | `doRustRealityDeferredFn` + `NewDeferredRustConn` |
| kTLS promotion | ~30 | `EnableKTLSOutcome()` + outcome handling |
| kTLSListener (XHTTP) | ~55 | Accept loop + `RustServerWithTimeout` |
| Loopback guard (Patch 1 target) | ~15 | `isLoopbackAddr` check removal |
| **Total** | **~150** | |

**Infrastructure supporting acceleration decisions**:

| Component | Lines | What it does |
|-----------|-------|--------------|
| native_policy.go | 675 | Policy modes, circuit breaker, scope keying |
| TCP hub.go telemetry | ~170 | 34 atomic counters + snapshot logging |
| XHTTP hub.go telemetry | ~200 | 42 atomic counters + snapshot logging |
| kREALITYListener.processConn | ~170 | Error handling + telemetry per failure mode |
| fallback_accel.go | 206 | Runtime recovery context, handoff eligibility |
| proxy.go recovery/regression | ~200 | shouldReport/maybeReport feedback functions |
| pipeline/decision.go | 153 | Decision types, copy-gate evaluation |
| pipeline/state_machine.go | 124 | DecideVisionPath, EvaluateCopyGate |
| **Total** | **~1,900** | |

**Ratio: ~13:1** (infrastructure to acceleration).

### Is This Justified?

Partially. The circuit breaker and recovery mechanism are necessary for
production safety. The loopback guard is important. The telemetry enables
debugging production issues. A proxy handling untrusted network traffic needs
defense-in-depth around any FFI boundary.

**What is NOT justified**:

1. **Full duplication between TCP and XHTTP** (Finding 1). Same schema, same
   failure modes, separate implementations.

2. **30+ string constants for decision reasons** (`pipeline/decision.go:76-127`).
   These exist for telemetry logging. They are never matched against at runtime
   (no `switch` on reason strings for control flow). They could be a single
   `fmt.Sprintf` at the log site.

3. **The 18-field DecisionSnapshot struct** (`pipeline/decision.go:130-153`).
   Used exclusively for logging. Every copy-loop iteration populates fields
   that are only read when the connection terminates and the snapshot is logged.
   The struct carries the weight of every acceleration path it might have taken,
   not just the one it did take.

### The Gravity Effect

When the observability scaffolding around a feature exceeds the feature by an
order of magnitude, the scaffolding shapes the engineering agenda. New ideas
get evaluated against "does the telemetry support this?" rather than "does the
user benefit from this?" An LLM prompted to find "overlooked integration points"
will see this infrastructure and conclude there must be more integration points
to fill — exactly the high-dimensional rabbit hole that motivated this audit.

The correct response to "where are the overlooked acceleration points?" is not
"add more integration points" but "reduce the infrastructure-to-acceleration
ratio by consolidating what exists."

---

## V. Finding 4: Sockmap/Splice Irrelevance to XHTTP (Low — By Design)

### The Situation

XHTTP is the transport that benefits most from TLS-layer acceleration (kTLS),
because its outer TLS is active for the full session. But the extensive
sockmap/splice infrastructure has zero payoff for XHTTP because the proxy
sees `splitConn` (HTTP body abstraction), not raw sockets.

This is correct by design — the HTTP framing layer cannot be bypassed. But it
means:

- `ebpf/sockmap.go` (~600 lines) — no XHTTP benefit
- `proxy.go` splice dispatch (~200 lines) — no XHTTP benefit
- Copy-gate state machine in `pipeline/` — evaluates to `NotApplicable`
  immediately for XHTTP

The primary beneficiaries of sockmap/splice are direct TCP connections without
Vision or XHTTP framing — a narrow niche in the canonical deployment where most
traffic is XHTTP.

### Assessment

This is not a miscalculation. It is an honest architectural boundary. The
observation is that the acceleration infrastructure was designed for a broader
set of transports than the canonical deployment actually exercises. In the
canonical deployment, XHTTP's kTLS is the main payoff. Sockmap/splice primarily
benefit non-canonical deployments (direct TCP, no nginx shunter).

---

## VI. Finding 5: XHTTP Capabilities Probe (Low)

### The Situation

`xhttpCapabilitiesSummary()` (`splithttp/hub.go:647-664`) probes native
capabilities (kTLS, sockmap, splice) and caches them with an epoch counter.
This is called during kREALITYListener's per-connection `processConn()`.

The probe checks sockmap and splice capabilities that are irrelevant to XHTTP
(`CopyGateNotApplicable` always). The cached result includes `SockmapSupported`
and `SpliceSupported` fields that XHTTP never acts on.

### Assessment

The probe is cheap (cached, refreshed only on epoch change). The wasted fields
are four booleans. This is noise, not a problem. Noted for completeness.

---

## VII. Summary Table

| Finding | Severity | Category | Lines involved | Recommendation |
|---------|----------|----------|----------------|----------------|
| Telemetry duplication (TCP/XHTTP) | High | Infrastructure waste | ~370 | Shared recorder type |
| Non-Vision kTLS without splice | Medium | Incomplete feature | ~30 | Type-assertion gap in IsRAWTransportWithoutSecurity |
| Infrastructure-to-acceleration ratio | Structural | Architecture smell | ~1,900 vs ~150 | Consolidate, don't expand |
| Sockmap/splice XHTTP irrelevance | Low | Correct boundary | N/A | Document, not fix |
| XHTTP capabilities probe waste | Low | Noise | ~4 fields | Not worth fixing |

---

## VIII. The Anti-Pattern: Searching for Integration Points

The GPT-5.4-xhigh session that prompted this audit illustrates a specific
failure mode of LLM-assisted architecture analysis:

**Input**: "Find overlooked acceleration integration points."

**LLM behavior**: The model scans the codebase, sees extensive acceleration
infrastructure (copy gates, splice dispatch, sockmap registration, kTLS
promotion, circuit breakers), and concludes that the infrastructure implies
more integration points should exist. It then proposes new acceleration points
at every stage where the infrastructure could theoretically connect but doesn't.

**Why this fails**: The infrastructure is not a template for future work. It is
the result of a specific set of deployment requirements that have been satisfied.
New integration points that "fill gaps" in the infrastructure add complexity to
paths that the canonical deployment doesn't exercise, while the canonical
deployment's main payoff (XHTTP kTLS) is already complete.

**The correct question is not**: "Where could we add acceleration?"

**The correct question is**: "Where is the canonical deployment leaving
performance on the table, and what is the minimum change to capture it?"

For the `perf` branch at `f5a28e50`, the answer is: Patch 1 (remove loopback
guard, ~15 lines) to enable Rust REALITY handshake + kTLS on non-loopback
deployments. Everything else is either already shipped, correctly gated for
future work, or irrelevant to the canonical deployment.
