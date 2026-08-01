package session

import (
	"net"
	"testing"
)

func TestSetCopyGateClearsReasonOnUnset(t *testing.T) {
	inb := &Inbound{}
	inb.SetCopyGate(CopyGateForcedUserspace, CopyGateReasonSecurityGuard)
	if inb.CopyGateReason() != CopyGateReasonSecurityGuard {
		t.Fatalf("reason=%v, want %v", inb.CopyGateReason(), CopyGateReasonSecurityGuard)
	}
	// Transition state to eligible and ensure reason is cleared to unspecified.
	inb.SetCanSpliceCopy(CopyGateEligible)
	if got := inb.CopyGateReason(); got != CopyGateReasonUnspecified {
		t.Fatalf("reason=%v, want %v", got, CopyGateReasonUnspecified)
	}
}

func TestSetCopyGateStoresUnspecifiedReason(t *testing.T) {
	inb := &Inbound{}
	inb.SetCopyGate(CopyGateEligible, CopyGateReasonUnspecified)
	if got := inb.CopyGateReason(); got != CopyGateReasonUnspecified {
		t.Fatalf("reason=%v, want %v", got, CopyGateReasonUnspecified)
	}
}

func TestSetCopyGateClearsReasonOutbound(t *testing.T) {
	ob := &Outbound{}
	ob.SetCopyGate(CopyGateForcedUserspace, CopyGateReasonSecurityGuard)
	if ob.CopyGateReason() != CopyGateReasonSecurityGuard {
		t.Fatalf("reason=%v, want %v", ob.CopyGateReason(), CopyGateReasonSecurityGuard)
	}
	ob.SetCanSpliceCopy(CopyGateEligible)
	if got := ob.CopyGateReason(); got != CopyGateReasonUnspecified {
		t.Fatalf("reason=%v, want %v", got, CopyGateReasonUnspecified)
	}
}

func TestCopyGateReasonVisionNoDetachString(t *testing.T) {
	if got := CopyGateReasonVisionNoDetach.String(); got != "vision_no_detach" {
		t.Fatalf("reason string=%q, want %q", got, "vision_no_detach")
	}
}

func TestVisionRawWriterProofIsBoundToPhysicalSocket(t *testing.T) {
	first := &net.TCPConn{}
	second := &net.TCPConn{}
	proof := &VisionRawWriterProof{}
	if proof.CommitRequired() {
		t.Fatal("empty proof must not require a commit")
	}
	proof.RequireCommit()
	if !proof.CommitRequired() {
		t.Fatal("proof should record the Vision writer requirement")
	}
	if proof.ReadyFor(first) {
		t.Fatal("required proof must not be ready before a physical write")
	}
	proof.Commit(first)
	if !proof.ReadyFor(first) {
		t.Fatal("proof should report the committed physical writer")
	}
	if proof.ReadyFor(second) {
		t.Fatal("commit proof must not authorize a different physical writer")
	}
}
