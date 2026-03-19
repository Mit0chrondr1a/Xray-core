# Postmortem: Hallucinated Egress Caps and DNS Misclassified into Acceleration Pipeline

Date: 2026-03-04  
Branch context: performance-focused branch with REALITY + VISION + eBPF/kTLS work

## Intent of This Report

This report consolidates why the failure pattern happened, why it lasted longer than it should have, and how an "autocompleter-style" coding workflow contributed to tunnel-vision patches instead of rapid root-cause isolation.

The goal is engineering learning, not blame theater.

## Executive Summary

Two failures overlapped:

1. DNS traffic (especially DoT/port 53 over loopback REALITY ingress) was allowed into acceleration/handover paths that are optimized for long-lived bulk flows, not short latency-critical control flows.
2. A separate egress fast-fail/penalty framework was introduced and iterated without strong causal proof, creating self-imposed control limits ("caps") that looked like resilience features but behaved as failure amplifiers under this workload.

This produced the observed "cork-pop-cork" behavior: rare brief response windows, then jam/stall again.

## Evidence Anchors

### 1) DNS flow observed in logs

`error.log21` repeatedly shows:

- `proxy/vless/inbound: received request for tcp:1.0.0.1:53`
- `transport/internet/tcp: dialing TCP to tcp:1.0.0.1:53`
- `proxy: CopyRawConn loopback guard active: disabling splice/sockmap ... writer_addrs=127.0.0.1:2036->127.0.0.1:*`

No `udp:1.0.0.1:*` and no `:853` records are present in the sampled log.

### 2) DNS protocol rewrite logic exists

`app/dispatcher/default.go` rewrites `tcp:53 -> udp:53` unless suppressed by env flag or loopback ingress guard:

- `app/dispatcher/default.go:540`
- `app/dispatcher/default.go:547`
- `app/dispatcher/default.go:548`

This is a high-impact behavioral switch that can alter resolver semantics if applied outside strict scope.

### 3) DNS explicitly forced out of acceleration on loopback after regressions

`proxy/proxy.go` now short-circuits loopback DNS to userspace copy:

- `proxy/proxy.go:1565`
- `proxy/proxy.go:1568`
- `proxy/proxy.go:1573`

This was added to realign with main-branch behavior for DNS reliability.

### 4) Rust REALITY loopback guard added later

`transport/internet/tcp/hub.go` now skips Rust deferred REALITY on loopback ingress:

- `transport/internet/tcp/hub.go:488`
- `transport/internet/tcp/hub.go:492`

This indicates the original deferred path was too risky for the loopback DNS/control-plane profile.

### 5) kTLS promotion bypass added for DNS and Vision flows

`transport/internet/tcp/dialer.go` skips kTLS promotion for DNS/vision:

- `transport/internet/tcp/dialer.go:149`
- `transport/internet/tcp/dialer.go:153`

### 6) Egress penalty subsystem became effectively inert, but scaffolding remains

Current code keeps the structure, counters, and state map, but fast-fail/penalty decisions are disabled:

- `proxy/freedom/freedom.go:292` (`shouldFastFailEgressDial` returns no block)
- `proxy/freedom/freedom.go:297` (`noteEgressDialFailure` no-op)
- `proxy/freedom/freedom.go:302` (`clearEgressDialPenalty` still manipulates map)

This is "dead governance scaffolding": conceptually active in architecture, practically inert in behavior.

## Comparison: `sockmap-big-provider` Analysis vs Real Bug

Reference document:

- `docs/sockmap-big-provider-regression-analysis-2026-03-03.md`

### What that analysis got right

1. It correctly identified a real risk class for generic high-volume traffic:
   - aggressive sockmap adoption plus long fallback waits can cause jamming on some destinations.
2. It correctly noted "transport success != app success":
   - `forward_success` can look healthy while user-perceived success is bad.

### Where it mismatched this DNS incident

The DNS incident discussed in this thread was not primarily "big-provider sockmap policy mismatch."  
By direct log evidence (`error.log20`/`error.log21`), traffic in question was dominated by:

- `tcp:1.0.0.1:53`
- loopback REALITY ingress path on `127.0.0.1:2036`

This is resolver control-plane traffic, not the same class as bulk app traffic to large provider IP pools.

### Workaround chain vs actual bug (comparison matrix)

| Stage | Working interpretation at the time | Workaround class introduced | What happened | Retrospective verdict |
|---|---|---|---|---|
| A | Sockmap on strict egress might be too aggressive | More fallback/de-accel heuristics | Some partial relief, but DoT still cork-pop/stalled | Partially relevant for generic traffic, not root cause for this DNS case |
| B | Dial failures need protective fast-fail/penalty state | Egress penalty/cooldown scaffolding in freedom | Added complexity and potential self-throttling; no deterministic DNS recovery | Wrong control loop for this incident |
| C | DNS over TCP:53 should be "fast-pathed" by rewriting to UDP | Dispatcher TCP->UDP rewrite path | Semantic divergence from baseline and harder RCA | High-risk for correctness unless tightly scoped |
| D | Rust deferred/accel path still acceptable for loopback DNS | Mixed Vision/kTLS/deferred path toggles | DoQ improved earlier than DoT; DoT remained unstable | Signal of protocol-path mismatch, not solved by more heuristics |
| E | Enforce baseline semantics for loopback DNS | Explicit bypasses and loopback guards for DNS control-plane | Reliability and parity improved; behavior became explainable | Correct direction |

### Real bug statement (final)

The real bug was architectural misclassification:

1. DNS control-plane traffic was treated as acceleration-candidate data-plane traffic.
2. Stateful heuristic caps were added on top, turning uncertainty into self-imposed constraints.
3. The branch drifted from baseline DNS semantics, so every new patch increased ambiguity.

## Technical Failure Mode (Under the Hood)

### Stage A: DNS treated as acceleration candidate

DNS control traffic entered VISION/deferred-handover/acceleration decision space. Those mechanisms are sensitive to detach timing, kTLS readiness, and zero-copy eligibility, which are poor fit for short resolver transactions.

### Stage B: Heuristic caps introduced without causal closure

Egress penalty/fast-fail controls were layered in as reaction to dial failures/timeouts, but without proving they were primary cause of DNS stalls. This added control-loop state that could suppress recovery attempts during transient resolver turbulence.

### Stage C: Divergence from baseline widened troubleshooting radius

Once DNS behavior diverged from main branch (rewrite rules, bypass toggles, penalty semantics), each new patch had to be debugged against both upstream network behavior and branch-specific control logic. RCA complexity expanded faster than confidence.

### Stage D: Residual complexity persisted after partial fixes

Even after direct mitigations worked (DoQ improved), latent scaffolding and mixed policy layers still left DoT vulnerable and made client-dependent behavior (Android vs OpenWrt) harder to reason about deterministically.

## Agent Behavior Failure Analysis

This section explains the "autocompleter trait" failure pattern.

### 1) Local plausibility over global invariants

Patch choices were often locally reasonable ("reduce retries", "avoid stalled path", "add penalty"), but not continuously checked against global invariant:

- DNS control-plane must preserve baseline semantics first; acceleration is optional.

### 2) Confirmation by noisy proxy metrics

"Network flow number increased" was repeatedly over-interpreted as progress, even when UX remained stalled. This encouraged iterative heuristic tuning instead of immediate baseline parity checks.

### 3) Monotonic complexity bias

The agent pattern preferred adding another guard/heuristic instead of deleting wrong abstractions. This is a common autocomplete failure mode: generating "next plausible patch" rather than questioning whether the previous frame is wrong.

### 4) Weak falsification discipline

Stronger self-correction would have required a hard stop and falsification matrix:

- "If baseline binary works in identical environment, branch-induced control logic is suspect until disproven."

That rule was applied late, not early.

### 5) Sunk-cost lock-in

Once penalty/fast-fail scaffolding existed, subsequent reasoning tended to preserve it and tune it, even when evidence suggested it was orthogonal or harmful for DNS.

## Why Self-Correction Was Delayed

1. Symptoms were intermittent ("pop then stall"), enabling misattribution.
2. Multiple moving parts changed at once (VISION bypass, loopback guards, rustls/kTLS handover, freedom dial policy).
3. Baseline parity was not treated as a mandatory gate for DNS early enough.
4. The agent optimized for "keep shipping patches" instead of "delete and simplify when hypothesis is weak."

## Impact

- Extended debugging cycle.
- Repeated client-visible DNS startup latency and stalls.
- Increased branch complexity with low-confidence controls.
- Additional cognitive load for operators and reviewers.

## Corrective Direction (What We Should Institutionalize)

### Code-level rules

1. DNS-first reliability rule:
   - DNS control-plane defaults to baseline-safe path.
   - Opt-in acceleration only with explicit proof and isolated guard rails.
2. Delete dead control scaffolding:
   - Remove inert fast-fail/penalty structures if policy is "fully disabled."
3. Keep rewrite behavior explicit and auditable:
   - `tcp:53 -> udp:53` conversion must be narrow, test-covered, and easy to disable.

### Process-level rules for coding agents

1. Baseline parity gate (mandatory):
   - If main branch works in same environment, new branch must match for DNS before adding heuristics.
2. Falsification-first loop:
   - Require one disproving test per hypothesis before adding any new stateful control.
3. Complexity budget:
   - Two failed heuristic patches in same area triggers mandatory simplification/rollback of that area.
4. No "metric-only success":
   - Throughput/flow counters are secondary; user-visible success criteria are primary.

## Immediate Follow-ups

1. Remove remaining egress penalty scaffolding in `proxy/freedom/freedom.go` if policy remains permanently disabled.
2. Add regression tests for:
   - loopback DNS on `127.0.0.1:2036`
   - DoT stability under startup bursts
   - no accidental `tcp:53 -> udp:53` rewrite on guarded ingress
3. Add a short architecture note:
   - "DNS is control-plane, not acceleration candidate by default."

## Correct Solutions (Consolidated)

These are the fixes that align with the confirmed failure mode:

1. Keep DNS on baseline-safe path under loopback ingress:
   - bypass acceleration in `CopyRawConn` for loopback DNS (`proxy/proxy.go`).
2. Skip Rust deferred REALITY on loopback ingress:
   - use Go REALITY path for that scope (`transport/internet/tcp/hub.go`).
3. Skip kTLS promotion for DNS control paths:
   - handshake without kTLS promotion for DNS/vision in TCP dialer (`transport/internet/tcp/dialer.go`).
4. Keep VISION bypass for loopback DNS/UDP control flows:
   - use `ShouldBypassVisionDNS` and `ShouldBypassVisionLoopbackUDP` gates (`proxy/vless/encoding/addons.go`, inbound/outbound call sites).
5. Fully unwind self-imposed fast-fail/penalty behavior:
   - keep it disabled and remove dead scaffolding in follow-up cleanup.

## Bottom Line

The core issue was not just a bug in one function. It was a control-theory and workflow failure: DNS was put inside an optimization envelope that was too stateful, too heuristic, and too eager.  
The agent then reinforced that frame with autocomplete-style incremental patches instead of stepping back to enforce baseline semantics first.
