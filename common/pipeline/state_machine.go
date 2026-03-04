package pipeline

import "strings"

// DecisionInput captures the key factors for handover/acceleration selection.
type DecisionInput struct {
	DeferredTLSActive bool
	LoopbackPair      bool
	Caps              CapabilitySummary
	// ReaderCrypto / WriterCrypto accept canonical values from callers,
	// e.g. "none", "ktls-both", "ktls-tx-only", "ktls-rx-only", "userspace-tls".
	ReaderCrypto string
	WriterCrypto string
}

// DecideVisionPath returns a DecisionSnapshot with chosen path/reason based on inputs.
// It centralizes the prechecks so callers (proxy, XHTTP) can avoid divergent heuristics.
func DecideVisionPath(in DecisionInput) DecisionSnapshot {
	snap := DecisionSnapshot{
		Path:   PathUserspace,
		Reason: ReasonDefault,
		Caps:   in.Caps,
	}

	// If splice/zero-copy is unavailable, stay in userspace early to avoid
	// bouncing through later fallback branches (keeps logs/telemetry honest).
	if !in.Caps.SpliceSupported {
		snap.Reason = ReasonSpliceCapabilityDisabled
		return snap
	}

	// Safety: if deferred TLS is still active, stay in userspace.
	if in.DeferredTLSActive {
		snap.Reason = ReasonDeferredTLSGuard
		return snap
	}

	readerCrypto := normalizeDecisionCryptoHint(in.ReaderCrypto)
	writerCrypto := normalizeDecisionCryptoHint(in.WriterCrypto)
	if readerCrypto == "userspace-tls" || writerCrypto == "userspace-tls" {
		if in.LoopbackPair {
			snap.Reason = ReasonLoopbackUserspaceTLSGuard
		} else {
			snap.Reason = ReasonUserspaceTLSGuard
		}
		return snap
	}

	// Start optimistic with splice; sockmap decided later by caller.
	snap.Path = PathSplice
	snap.Reason = ReasonSplicePrimary

	// Loopback allowed after detach; no extra change needed here.
	return snap
}

func normalizeDecisionCryptoHint(v string) string {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "userspace", "userspace_tls", "userspace-tls", "user-space-tls":
		return "userspace-tls"
	default:
		return strings.TrimSpace(strings.ToLower(v))
	}
}
