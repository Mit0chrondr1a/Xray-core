# Acceleration Status Report: perf Branch + GPT-5.4-xhigh Agent Behavior Analysis

Date: 2026-04-01

Architect: Claude Opus 4.6 (sole authoritative architect per project owner directive)

## 1. Canonical Deployment Shape

```
Internet → nginx (SNI shunt)
              ├─ REALITY listener (Vision/TCP, loopback 127.0.0.1)
              │     ├─ Vision TCP direct (command=1)
              │     ├─ Mux parent (command=0) carrying:
              │     │     ├─ XUDP sessions (browsing, streaming)
              │     │     └─ DoQ (udp:1.0.0.1:853)
              │     └─ Fallback (non-VLESS probes → nginx/other)
              └─ XHTTP listener (separate port or H2/H3)
```

Operator uses `PREFER_NATIVE` policy mode. Inbound tag contains "vision".

## 2. Acceleration Matrix

### 2.1 Inbound REALITY Listener (Vision-tagged, loopback)

| Connection type | TLS handshake | kTLS | Sockmap | Splice | Status |
|---|---|---|---|---|---|
| Vision TCP direct | Go REALITY | No | No | Post-detach only | **Blocked by vision guard** |
| Mux parent (Vision) | Go REALITY | No | No (userspace demux) | No | **Blocked by vision guard** |
| Mux parent (non-Vision flow="") | Go REALITY | No | No (userspace demux) | No | **Blocked by vision guard** |
| Fallback probe | Go REALITY | No | N/A | N/A | **Blocked by vision guard** |

**Why everything is blocked:** Two guards stack:

1. `vision_inbound_go_fallback_guard` (`native_policy.go:655`): Tag contains "vision" →
   `SkipByPolicy=true`. Blocks ALL native REALITY on this listener.

2. `loopback_listener_auto_guard` (`native_policy.go:660`): `isLoopbackAddr(localAddr)` →
   `SkipByPolicy=true` in AUTO mode. On `PREFER_NATIVE`, this guard is skipped (line 660
   checks `AUTO` mode only). But the vision guard fires first and is unconditional
   (except `FORCE_NATIVE`).

**Result:** Zero Rust handshakes, zero kTLS, zero eBPF sockmap on the primary
production listener. 100% Go REALITY userspace TLS.

### 2.2 XHTTP Listener

| Component | Path | kTLS | Sockmap | Status |
|---|---|---|---|---|
| XHTTP + standard TLS server | `kTLSListener` → `RustServerWithTimeout` → `KTLSPlaintextConn` | **Yes** (mandatory) | No (splitConn) | **Active** |
| XHTTP + REALITY server | `kREALITYListener` → Rust deferred → kTLS promotion | **Yes** (when eligible) | No (splitConn) | **Active** |
| XHTTP + REALITY server (fallback) | `goreality.NewListener` → Go REALITY | No | No | Fallback path |
| XHTTP client (standard TLS) | `rustClientWithContext` or `HandshakeAndEnableKTLS` | **Yes** | No | **Active** |
| XHTTP client (REALITY) | `reality.UClient()` → Rust REALITY → kTLS | **Yes** | No | **Active** |

**Why no sockmap:** XHTTP proxy sees `splitConn` (HTTP body abstraction), not `*net.TCPConn`.
Sockmap requires raw socket pairs. This is a fundamental transport-layer constraint, not a
guard or policy issue.

**Result:** XHTTP is the most accelerated transport. Both server and client get Rust TLS +
kTLS. No sockmap possible by design.

### 2.3 Outbound (All Transports)

| Connection type | Path | kTLS | Status |
|---|---|---|---|
| Non-Vision TLS outbound | `rustClientWithContext` (`dialer.go:144`) | **Yes** | **Active** |
| Non-Vision REALITY outbound | Rust REALITY client (`reality.go:259`) → kTLS | **Yes** | **Active** |
| Vision TLS outbound | Go TLS client (`dialer.go:149-154`) | No | Vision flow gate blocks Rust |
| Vision REALITY outbound | Go uTLS REALITY (`reality.go:291+`) | No | Vision flow gate blocks Rust |

**Gate:** `session.VisionFlowFromContext(ctx)` at `dialer.go:143` and `reality.go:235`.
When Vision flow is active, outbound skips Rust TLS entirely. This is correct — kTLS
is irremovable from the socket, but Vision requires outer TLS stripping at command=2.

### 2.4 Non-Vision Inbound (Hypothetical Non-Vision-Tagged Listener)

| Connection type | TLS handshake | kTLS | Sockmap | Status |
|---|---|---|---|---|
| Non-Vision TCP (flow="") | Rust REALITY → DeferredRustConn | **Yes** (non-mux) | Eligible | **Active** |
| Non-Vision mux parent | Rust REALITY → DeferredRustConn | **No** (shared parent skip) | No (userspace demux) | Skip at `:758` |
| Fallback | DeferredRustConn → EnableKTLS | **Yes** | N/A | **Active** (`:440-462`) |

**Note:** This path only activates if the listener tag does NOT contain "vision". In the
canonical deployment, the primary listener IS Vision-tagged, so this path is irrelevant
for production traffic.

## 3. Rust Code Exercised vs Dead

### 3.1 Active in Production

| Component | Rust source | Exercised by |
|---|---|---|
| TLS client handshake | `tls.rs` ~1,500 lines | Outbound non-Vision TLS, XHTTP client |
| REALITY client handshake | `reality.rs` ~1,200 lines | Outbound non-Vision REALITY, XHTTP REALITY client |
| REALITY server handshake | `reality.rs` deferred path | XHTTP `kREALITYListener` server |
| kTLS install/promote | `tls.rs` kTLS functions | All Rust TLS paths (outbound, XHTTP, non-Vision inbound) |
| Vision padding | `vision.rs` ~2,000 lines | All Vision flows (pad/unpad/TLS-filter) |
| Blake3 hashing | `blake3.rs` | XUDP global ID (`xudp.go:68`), VLESS encryption key derivation |
| eBPF loader | `ebpf.rs` ~1,500 lines | Sockmap setup for eligible non-Vision pairs |
| SK_SKB + SK_MSG programs | `xray-ebpf/src/` ~1,500 lines | Kernel-level socket splicing |

### 3.2 Dead on Canonical Deployment (Blocked by Vision Guard)

| Component | Rust source | Would serve |
|---|---|---|
| REALITY server deferred handshake | `reality.rs` deferred path | Vision-tagged inbound (primary production traffic) |
| DeferredRustConn lifecycle | `tls.rs` DeferredSession | Vision TCP, mux parents, fallback on Vision listener |
| kTLS promotion for Vision inbound | `tls.rs` EnableKTLS path | Non-Vision connections arriving on Vision-tagged listener |

### 3.3 Linked but No Active Call Sites

| Component | Rust source | Notes |
|---|---|---|
| MPH matcher | `mph.rs` | No call sites found in Go code |
| GeoIP set matching | `ipset.rs` | No call sites found in Go code |

## 4. Vision Padding: CGO Cost Assessment

**Status:** Unresolved. Not proven net-positive or net-negative.

The Rust Vision padding (`vision.rs`) is called for every buffer during the TLS handshake
phase (~100 calls per connection). The Rust path uses a thread-local 4KB RNG cache to
amortize `getrandom` syscalls. The Go fallback (`xtlsPaddingGoFallback` at `proxy.go:1667`)
calls `crypto/rand.Read` per random number.

**Prior analysis** (referenced by project owner): CGO thread pinning cost outweighs
benefit; padding should use Go fallback.

**Dev finding (2026-04-01):** On this machine (Go 1.26.1), `crypto/rand.Read` still goes
through `sysrand.Read` → `unix.GetRandom` per call. No userspace ChaCha8 buffer on the
default non-FIPS path. The Rust RNG cache therefore provides real syscall amortization.

**Unresolved trade-off:**
- Rust benefit: ~75 fewer `getrandom` syscalls during handshake
- CGO cost: ~100 thread pinning events × ~200-600ns each
- Net: depends on `getrandom` latency on the specific kernel/hardware
- Needs benchmarking, not theoretical analysis

**Current state:** Rust path is the primary path (`proxy.go:1644`). Go fallback fires
only on Rust error (`proxy.go:1646-1649`).

## 5. DeferredRustConn: Post-kTLS Semantic Differences

This section documents the undiagnosed root cause of the DoQ regression when the vision
guard was removed (Phase 3 attempt, rolled back).

### 5.1 DeferredRustConn Read After kTLS

```go
// tls.go:1010-1039
func (c *DeferredRustConn) Read(b []byte) (int, error) {
    if n := c.consumeDeferredReadCache(b); n > 0 {
        return n, nil  // serve cached data first
    }
    // ...
    if ktlsActive {
        // Serve drained plaintext from Rust→kTLS transition
        if c.drainedOff < len(c.drainedData) {
            n := copy(b, c.drainedData[c.drainedOff:])
            // ...
            return n, nil
        }
        // Then: raw kTLS reads
        return c.rawConn.Read(b)  // kernel TLS
    }
}
```

**Semantic difference from Go TLS + kTLS:** A Go `tls.Conn` with kTLS promotion has no
`drainedData` phase. All reads go directly to the kernel. DeferredRustConn serves
`drainedData` first (bytes the Rust session read ahead during handshake), then switches
to kernel reads. If a mux frame straddles the drained/kTLS boundary, the first N bytes
come from `drainedData` and the rest from `rawConn.Read`. Semantically correct but
creates a read-size discontinuity that may affect mux frame timing.

### 5.2 DeferredRustConn Write After kTLS

```go
// tls.go:1321-1326
if ktlsActive {
    n, err := c.rawConn.Write(b)
    if err == nil {
        ktlsAfterWrite(n, handler, &c.writeRecords, &c.rotationFailures, c.rawConn.Close)
    }
    return n, err
}
```

**Semantic difference:** Identical to Go TLS kTLS write path. No meaningful divergence.

### 5.3 Deadline Tracking

```go
// tls.go:1961-1980
func (c *DeferredRustConn) SetReadDeadline(t time.Time) error {
    c.deadlineMu.Lock()
    c.readDeadline = t        // local mirror
    c.deadlineMu.Unlock()
    return c.rawConn.SetReadDeadline(t)  // also set on socket
}
```

**Semantic difference:** DeferredRustConn keeps a mirrored copy of deadlines (`deadlineMu`
+ `readDeadline`/`writeDeadline`) AND forwards to the raw socket. Go `tls.Conn` only
sets on the socket. The mirrored state is used during deferred Rust I/O (pre-kTLS) but
persists after promotion. Extra lock acquisition per deadline set, but functionally
equivalent.

### 5.4 UnwrapRawConn Behavior

```go
// proxy.go:1915-1919
} else if dc, ok := conn.(*tls.DeferredRustConn); ok {
    if !dc.IsDetached() && !dc.KTLSEnabled().Enabled {
        // Deny raw unwrap: keep the deferred connection intact
        return dc, readCounter, writerCounter, handler
    }
```

**Semantic difference:** `UnwrapRawConn` refuses to peel a DeferredRustConn that is
neither detached nor kTLS-promoted. This affects `determineSocketCryptoHintRecurse`
(`proxy.go:2038-2054`) — a non-promoted DeferredRustConn gets `CryptoUserspaceTLS`
hint, preventing sockmap. After kTLS promotion, it correctly returns
`CryptoKTLSBoth` + raw conn.

### 5.5 Root Cause Assessment

The dev confirmed (2026-04-01): the `drainedData` / kTLS boundary is the most concrete
semantic difference. The deadline mirroring and `UnwrapRawConn` behavior are functionally
equivalent after promotion. Option D (instrumented reproduction comparing TLS session
parameters and mux frame timing) remains the right investigation path.

## 6. Guard Stack on Canonical Deployment

For the primary Vision-tagged REALITY listener on loopback:

```
shouldAttemptNativeRealityForAddr()
  ├─ debug disable check                    → pass
  ├─ policy mode check (PREFER_NATIVE)      → pass
  ├─ eligibility (native available, kTLS)   → pass
  ├─ vision_inbound_go_fallback_guard       → BLOCKED (tag contains "vision")
  │     ↑ game over for native REALITY
  ├─ loopback_listener_auto_guard           → would block in AUTO, skipped in PREFER_NATIVE
  ├─ circuit breaker                        → never reached
  └─ mode switch                            → never reached
```

The vision guard is the sole active blocker. The loopback guard would also block in
AUTO mode but is moot because the vision guard fires first.

## 7. Quantitative Summary

| Metric | Value |
|---|---|
| Total Rust lines (xray-rust + xray-ebpf) | ~19,000 |
| Rust lines exercised in production | ~8,700 (vision.rs, tls.rs client, reality.rs client, blake3, ebpf) |
| Rust lines dead on canonical deployment | ~5,300 (reality.rs server deferred, tls.rs DeferredSession inbound) |
| Rust lines linked but unused | ~5,000 (mph.rs, ipset.rs, dead code) |
| kTLS-accelerated paths | XHTTP server+client, outbound non-Vision TLS, non-Vision inbound |
| kTLS-blocked paths | All Vision-tagged inbound (guard), Vision outbound (flow gate) |
| eBPF sockmap eligible | Non-Vision raw TCP + kTLS pairs only |
| eBPF sockmap impossible | XHTTP (splitConn), Vision (CanSpliceCopy), mux parents (userspace demux) |

## 8. What Would Unlock the Remaining Acceleration

| Blocker | What it blocks | Resolution path |
|---|---|---|
| `vision_inbound_go_fallback_guard` | Native REALITY on Vision-tagged listeners (~70% of inbound traffic) | Option D: root-cause DoQ regression on kTLS-promoted DeferredRustConn mux parents |
| Vision flow gate (outbound) | Rust TLS for Vision outbound | By design — kTLS is incompatible with Vision command=2 TLS stripping |
| Mux parent kTLS skip | kTLS on DeferredRustConn mux parents | Depends on Option D; consumed-handle blast radius also a factor |
| `splitConn` abstraction | eBPF sockmap for XHTTP | Fundamental — proxy never sees raw socket |

The single highest-impact unlock is resolving the vision guard. Everything else is
either by-design (Vision outbound, splitConn) or depends on the same root cause
(mux parent kTLS).

---

## Appendix A: Collaboration Pattern with Dev (GPT-5.4-xhigh)

### Role Division

I serve as sole authoritative architect. The dev (GPT-5.4-xhigh) implements, tests at
runtime, and provides ground-truth feedback from deployment logs. The project owner
mediates when findings conflict.

### Effective Collaboration Pattern

1. **Architect produces plan** → dev reviews for feasibility and safety gaps →
   architect revises → dev implements → runtime evidence validates or disproves.

2. **Dev's runtime evidence is authoritative over theoretical analysis.** When the dev
   reports "I implemented Step A and kTLS-promoted mux parents still broke DoQ," that
   overrides any amount of code-level safety reasoning. This was the key lesson from
   the Phase 3 attempt.

3. **Plans should be handed as complete documents** with explicit file paths, line
   numbers, before/after code, and test expectations. The dev works best with concrete
   specifications, not architectural direction.

### Dev's Working Style: Logical/Behavioral Patterns

**Strengths:**

- **Meticulous source verification.** Checks actual file contents against claims. Found
  that Go 1.26.1 `crypto/rand` does NOT buffer (contradicting my claim). Found that Step A
  was implemented before testing (contradicting my assumption). Cites specific file:line
  evidence for every assertion.

- **Precise severity grading.** Consistently uses High/Medium/Low with calibrated
  thresholds. "High" means the conclusion is wrong; "Medium" means the wording is
  too strong; "Low" means a minor imprecision.

- **Honest about what was tested.** Reports both successes and failures transparently.
  Doesn't hide retreats or frame them as planned outcomes. The "What We Retreated From"
  section was unprompted and accurate.

- **Conservative safety instinct.** Prefers guards, skips, and retreats over aggressive
  acceleration. This is a feature for production code, not a weakness.

- **Precise architectural language.** Distinguishes "the handshake itself is not
  incompatible" from "the DeferredRustConn handover state is undiagnosed." Does not
  overstate or conflate.

**Patterns to watch:**

- **Tends to frame retreats as completed work** rather than blocked work. "Where We
  Landed" presented the vision guard restoration as an achievement ("UX regression
  is gone") rather than acknowledging that the branch delivers zero acceleration on
  its primary traffic path. The project owner correctly pushed back on this.

- **May accept local optima.** Once DoQ regressed, the dev retreated fully rather than
  investigating the root cause of the kTLS-success/DoQ-failure paradox. The retreat
  was operationally correct (restore UX parity with main), but the investigation gap
  remains. Future work needs to push past "it regressed, so revert" to "why did it
  regress with kTLS active?"

- **Precision can slow convergence.** Multiple rounds of "your wording is too strong"
  refinement are valuable for documentation accuracy but can delay reaching actionable
  conclusions. The architect should front-load precise language to reduce review cycles.

### Dev's Pressure Handling

- **Under time pressure:** Makes operationally sound decisions (restore guard, preserve
  UX) without cutting corners on correctness. Does not introduce new bugs under pressure.

- **Under architectural disagreement:** Responds with evidence, not assertions. When I
  claimed missing Step A explained the retreat, the dev responded with specific code
  references showing Step A was implemented. Does not defer to authority without evidence.

- **Under ambiguity:** Prefers conservative defaults. When the DoQ root cause was unclear,
  chose the maximally safe option (restore guard entirely) rather than trying intermediate
  positions. This is the right instinct for production but means investigation stalls
  need external push.

### Recommended Architect-Dev Protocol

1. Architect delivers plan with explicit code diffs and test expectations.
2. Dev reviews for feasibility, grades findings by severity.
3. Architect revises based on High/Medium findings only (Low deferred).
4. Dev implements and deploys.
5. Runtime evidence feeds back. If plan is disproved, dev proposes retreat scope;
   architect validates and documents the finding.
6. Root-cause investigation of failures is explicitly assigned (not left as "future
   work" indefinitely).
