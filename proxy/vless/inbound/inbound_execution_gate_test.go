package inbound

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

func TestApplyVisionExecutionGateDeferredPathUsesPendingDetach(t *testing.T) {
	inbound := &session.Inbound{}

	applyVisionExecutionGate(inbound, &protocol.RequestHeader{Command: protocol.RequestCommandTCP}, true)

	if got := inbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("inbound state=%v, want pending_detach", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("inbound reason=%v, want unspecified", got)
	}
}

// Go TLS / Go REALITY Vision flows must keep the upstream contract: start in
// pending-detach so the response leg can splice after the direct-copy switch.
// Forcing them to userspace made the production listener slower than upstream.
func TestApplyVisionExecutionGateGoTLSPathUsesPendingDetach(t *testing.T) {
	inbound := &session.Inbound{}

	applyVisionExecutionGate(inbound, &protocol.RequestHeader{Command: protocol.RequestCommandTCP}, false)

	if got := inbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("inbound state=%v, want pending_detach", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("inbound reason=%v, want unspecified", got)
	}
}

// A security guard set before the gate is applied (full-random XorConn,
// non-RAW transport, nested security conn) must never be widened.
func TestApplyVisionExecutionGateGoTLSPathKeepsSecurityGuard(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonSecurityGuard)

	applyVisionExecutionGate(inbound, &protocol.RequestHeader{Command: protocol.RequestCommandTCP}, false)

	if got := inbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("inbound state=%v, want forced userspace", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonSecurityGuard {
		t.Fatalf("inbound reason=%v, want security_guard", got)
	}
}

func TestApplyVisionExecutionGateMuxParentUsesSecurityGuard(t *testing.T) {
	inbound := &session.Inbound{}

	applyVisionExecutionGate(inbound, &protocol.RequestHeader{Command: protocol.RequestCommandMux}, true)

	if got := inbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("inbound state=%v, want forced userspace", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonSecurityGuard {
		t.Fatalf("inbound reason=%v, want security_guard", got)
	}
}
