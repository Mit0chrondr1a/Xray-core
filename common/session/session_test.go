package session

import "testing"

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

func TestCopyGateReasonVisionControlCompatString(t *testing.T) {
	if got := CopyGateReasonVisionControlCompat.String(); got != "vision_control_compat" {
		t.Fatalf("reason string=%q, want %q", got, "vision_control_compat")
	}
}

func TestCopyGateReasonVisionUplinkCompleteString(t *testing.T) {
	if got := CopyGateReasonVisionUplinkComplete.String(); got != "vision_uplink_complete" {
		t.Fatalf("reason string=%q, want %q", got, "vision_uplink_complete")
	}
}

func TestCopyGateReasonVisionCommandContinueString(t *testing.T) {
	if got := CopyGateReasonVisionCommandContinue.String(); got != "vision_command_continue" {
		t.Fatalf("reason string=%q, want %q", got, "vision_command_continue")
	}
}
