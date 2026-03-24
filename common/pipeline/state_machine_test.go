package pipeline

import "testing"

func TestDecideVisionPathSplicePrimary(t *testing.T) {
	got := DecideVisionPath(DecisionInput{
		Caps: CapabilitySummary{
			SpliceSupported: true,
		},
		ReaderCrypto: "none",
		WriterCrypto: "none",
	})

	if got.Path != PathSplice {
		t.Fatalf("Path=%q, want %q", got.Path, PathSplice)
	}
	if got.Reason != ReasonSplicePrimary {
		t.Fatalf("Reason=%q, want %s", got.Reason, ReasonSplicePrimary)
	}
}

func TestDecideVisionPathDeferredTLSGuard(t *testing.T) {
	got := DecideVisionPath(DecisionInput{
		DeferredTLSActive: true,
		Caps: CapabilitySummary{
			SpliceSupported: true,
		},
	})

	if got.Path != PathUserspace {
		t.Fatalf("Path=%q, want %q", got.Path, PathUserspace)
	}
	if got.Reason != ReasonDeferredTLSGuard {
		t.Fatalf("Reason=%q, want %s", got.Reason, ReasonDeferredTLSGuard)
	}
}

func TestDecideVisionPathUserspaceTLSGuard(t *testing.T) {
	got := DecideVisionPath(DecisionInput{
		Caps: CapabilitySummary{
			SpliceSupported: true,
		},
		ReaderCrypto: "userspace-tls",
		WriterCrypto: "none",
	})

	if got.Path != PathUserspace {
		t.Fatalf("Path=%q, want %q", got.Path, PathUserspace)
	}
	if got.Reason != ReasonUserspaceTLSGuard {
		t.Fatalf("Reason=%q, want %s", got.Reason, ReasonUserspaceTLSGuard)
	}
}

func TestDecideVisionPathLoopbackUserspaceTLSGuard(t *testing.T) {
	got := DecideVisionPath(DecisionInput{
		LoopbackPair: true,
		Caps: CapabilitySummary{
			SpliceSupported: true,
		},
		ReaderCrypto: "userspace_tls",
		WriterCrypto: "none",
	})

	if got.Path != PathUserspace {
		t.Fatalf("Path=%q, want %q", got.Path, PathUserspace)
	}
	if got.Reason != ReasonLoopbackUserspaceTLSGuard {
		t.Fatalf("Reason=%q, want %s", got.Reason, ReasonLoopbackUserspaceTLSGuard)
	}
}

func TestEvaluateCopyGateInboundForced(t *testing.T) {
	reason, gate, gateReason, copyPath, stop := EvaluateCopyGate(CopyGateInput{
		InboundGate:   CopyGateForcedUserspace,
		InboundReason: CopyGateReasonVisionBypass,
	})
	if !stop {
		t.Fatalf("stop=%v, want true", stop)
	}
	if reason != ReasonInboundForcedUserspace {
		t.Fatalf("reason=%q, want %q", reason, ReasonInboundForcedUserspace)
	}
	if gate != CopyGateForcedUserspace {
		t.Fatalf("gate=%v, want %v", gate, CopyGateForcedUserspace)
	}
	if gateReason != CopyGateReasonVisionBypass {
		t.Fatalf("gateReason=%v, want %v", gateReason, CopyGateReasonVisionBypass)
	}
	if copyPath != CopyPathUserspace {
		t.Fatalf("copyPath=%v, want %v", copyPath, CopyPathUserspace)
	}
}

func TestEvaluateCopyGateInboundNotApplicable(t *testing.T) {
	reason, gate, gateReason, copyPath, stop := EvaluateCopyGate(CopyGateInput{
		InboundGate:   CopyGateNotApplicable,
		InboundReason: CopyGateReasonTransportNonRawSplitConn,
	})
	if !stop {
		t.Fatalf("stop=%v, want true", stop)
	}
	if reason != ReasonCopyNotApplicable {
		t.Fatalf("reason=%q, want %q", reason, ReasonCopyNotApplicable)
	}
	if gate != CopyGateNotApplicable {
		t.Fatalf("gate=%v, want %v", gate, CopyGateNotApplicable)
	}
	if gateReason != CopyGateReasonTransportNonRawSplitConn {
		t.Fatalf("gateReason=%v, want %v", gateReason, CopyGateReasonTransportNonRawSplitConn)
	}
	if copyPath != CopyPathNotApplicable {
		t.Fatalf("copyPath=%v, want %v", copyPath, CopyPathNotApplicable)
	}
}

func TestEvaluateCopyGateOutboundForced(t *testing.T) {
	reason, gate, gateReason, copyPath, stop := EvaluateCopyGate(CopyGateInput{
		InboundGate: CopyGateEligible,
		OutboundGates: []CopyGateState{
			CopyGateForcedUserspace,
		},
		OutboundReason: []CopyGateReason{
			CopyGateReasonSecurityGuard,
		},
	})
	if !stop {
		t.Fatalf("stop=%v, want true", stop)
	}
	if reason != ReasonOutboundForcedUserspace {
		t.Fatalf("reason=%q, want %q", reason, ReasonOutboundForcedUserspace)
	}
	if gate != CopyGateForcedUserspace {
		t.Fatalf("gate=%v, want %v", gate, CopyGateForcedUserspace)
	}
	if gateReason != CopyGateReasonSecurityGuard {
		t.Fatalf("gateReason=%v, want %v", gateReason, CopyGateReasonSecurityGuard)
	}
	if copyPath != CopyPathUserspace {
		t.Fatalf("copyPath=%v, want %v", copyPath, CopyPathUserspace)
	}
}

func TestEvaluateCopyGateVisionNoDetachForced(t *testing.T) {
	reason, gate, gateReason, copyPath, stop := EvaluateCopyGate(CopyGateInput{
		InboundGate:   CopyGateForcedUserspace,
		InboundReason: CopyGateReasonVisionNoDetach,
	})
	if !stop {
		t.Fatalf("stop=%v, want true", stop)
	}
	if reason != ReasonVisionNoDetachUserspace {
		t.Fatalf("reason=%q, want %q", reason, ReasonVisionNoDetachUserspace)
	}
	if gate != CopyGateForcedUserspace {
		t.Fatalf("gate=%v, want %v", gate, CopyGateForcedUserspace)
	}
	if gateReason != CopyGateReasonVisionNoDetach {
		t.Fatalf("gateReason=%v, want %v", gateReason, CopyGateReasonVisionNoDetach)
	}
	if copyPath != CopyPathUserspace {
		t.Fatalf("copyPath=%v, want %v", copyPath, CopyPathUserspace)
	}
}

func TestEvaluateCopyGateNoStop(t *testing.T) {
	reason, gate, gateReason, copyPath, stop := EvaluateCopyGate(CopyGateInput{
		InboundGate: CopyGateEligible,
	})
	if stop {
		t.Fatalf("stop=%v, want false", stop)
	}
	if reason != "" {
		t.Fatalf("reason=%q, want empty", reason)
	}
	if gate != CopyGateUnset && gate != CopyGateEligible {
		t.Fatalf("gate=%v, want unset or eligible", gate)
	}
	if gateReason != CopyGateReasonUnspecified {
		t.Fatalf("gateReason=%v, want %v", gateReason, CopyGateReasonUnspecified)
	}
	if copyPath != CopyPathUnknown {
		t.Fatalf("copyPath=%v, want %v", copyPath, CopyPathUnknown)
	}
}
