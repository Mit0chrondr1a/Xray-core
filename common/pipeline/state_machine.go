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

// CopyGateInput centralizes early copy-path gate evaluation.
type CopyGateInput struct {
	InboundGate    CopyGateState
	InboundReason  CopyGateReason
	OutboundGates  []CopyGateState
	OutboundReason []CopyGateReason
}

// DecideVisionPath returns a DecisionSnapshot with chosen path/reason based on inputs.
// It centralizes the prechecks so callers (proxy, XHTTP) can avoid divergent heuristics.
func DecideVisionPath(in DecisionInput) DecisionSnapshot {
	snap := DecisionSnapshot{
		Path:           PathUserspace,
		Reason:         ReasonDefault,
		Caps:           in.Caps,
		CopyPath:       CopyPathUserspace,
		TLSOffloadPath: TLSOffloadUserspace,
		CopyGateState:  CopyGateUnset,
		CopyGateReason: CopyGateReasonUnspecified,
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
	snap.CopyPath = CopyPathSplice

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

// EvaluateCopyGate returns an early stop decision when copy path must stay in userspace
// or is not applicable. It keeps policy consistent across proxy and XHTTP callers.
// The returned reason is empty when no early decision is required.
func EvaluateCopyGate(in CopyGateInput) (reason string, gate CopyGateState, gateReason CopyGateReason, copyPath CopyPath, stop bool) {
	chooseReason := func(r CopyGateReason) CopyGateReason {
		if r == CopyGateReasonUnspecified {
			return CopyGateReasonUnspecified
		}
		return r
	}
	gate = in.InboundGate
	gateReason = chooseReason(in.InboundReason)
	if in.InboundGate == CopyGateForcedUserspace {
		if gateReason == CopyGateReasonVisionNoDetach {
			return ReasonVisionNoDetachUserspace, in.InboundGate, gateReason, CopyPathUserspace, true
		}
		if gateReason == CopyGateReasonVisionUplinkComplete {
			return ReasonVisionUplinkCompleteUserspace, in.InboundGate, gateReason, CopyPathUserspace, true
		}
		if gateReason == CopyGateReasonVisionCommandContinue {
			return ReasonVisionCommandContinueUserspace, in.InboundGate, gateReason, CopyPathUserspace, true
		}
		return ReasonInboundForcedUserspace, in.InboundGate, gateReason, CopyPathUserspace, true
	}
	if in.InboundGate == CopyGateNotApplicable {
		if gateReason == CopyGateReasonUnspecified {
			gateReason = CopyGateReasonTransportNonRawSplitConn
		}
		return ReasonCopyNotApplicable, in.InboundGate, gateReason, CopyPathNotApplicable, true
	}

	for i, g := range in.OutboundGates {
		var r CopyGateReason
		if i < len(in.OutboundReason) {
			r = chooseReason(in.OutboundReason[i])
		}
		switch g {
		case CopyGateForcedUserspace:
			if r == CopyGateReasonVisionNoDetach {
				return ReasonVisionNoDetachUserspace, g, r, CopyPathUserspace, true
			}
			if r == CopyGateReasonVisionUplinkComplete {
				return ReasonVisionUplinkCompleteUserspace, g, r, CopyPathUserspace, true
			}
			if r == CopyGateReasonVisionCommandContinue {
				return ReasonVisionCommandContinueUserspace, g, r, CopyPathUserspace, true
			}
			return ReasonOutboundForcedUserspace, g, r, CopyPathUserspace, true
		case CopyGateNotApplicable:
			if r == CopyGateReasonUnspecified {
				r = CopyGateReasonTransportNonRawSplitConn
			}
			return ReasonCopyNotApplicable, g, r, CopyPathNotApplicable, true
		}
	}

	return "", CopyGateUnset, CopyGateReasonUnspecified, CopyPathUnknown, false
}
