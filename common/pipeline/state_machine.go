package pipeline

// DecisionInput captures the key factors for handover/acceleration selection.
type DecisionInput struct {
	DeferredTLSActive bool
	LoopbackPair      bool
	Caps              CapabilitySummary
	ReaderCrypto      string
	WriterCrypto      string
}

// DecideVisionPath returns a DecisionSnapshot with chosen path/reason based on inputs.
// It centralizes the prechecks so callers (proxy, XHTTP) can avoid divergent heuristics.
func DecideVisionPath(in DecisionInput) DecisionSnapshot {
	snap := DecisionSnapshot{
		Path:   PathUserspace,
		Reason: "default",
		Caps:   in.Caps,
	}

	// If splice/zero-copy is unavailable, stay in userspace early to avoid
	// bouncing through later fallback branches (keeps logs/telemetry honest).
	if !in.Caps.SpliceSupported {
		snap.Reason = "splice_capability_disabled"
		return snap
	}

	// Safety: if deferred TLS is still active, stay in userspace.
	if in.DeferredTLSActive {
		snap.Reason = "deferred_tls_guard"
		return snap
	}

	// Start optimistic with splice; sockmap decided later by caller.
	snap.Path = PathSplice
	snap.Reason = "splice_primary"

	// Loopback allowed after detach; no extra change needed here.
	return snap
}
