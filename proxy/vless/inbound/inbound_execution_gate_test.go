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

func TestApplyVisionExecutionGateLegacyPathUsesUserspaceOnly(t *testing.T) {
	inbound := &session.Inbound{}

	applyVisionExecutionGate(inbound, &protocol.RequestHeader{Command: protocol.RequestCommandTCP}, false)

	if got := inbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("inbound state=%v, want forced userspace", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("inbound reason=%v, want unspecified", got)
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
