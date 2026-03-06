package splithttp

import (
	"testing"

	"github.com/xtls/xray-core/common/pipeline"
)

func TestApplyXHTTPCopyGate(t *testing.T) {
	decision := pipeline.DecisionSnapshot{
		CopyGateState:  pipeline.CopyGateUnset,
		CopyGateReason: pipeline.CopyGateReasonUnspecified,
		CopyPath:       pipeline.CopyPathUnknown,
	}
	applyXHTTPCopyGate(&decision)

	if decision.CopyGateState != pipeline.CopyGateNotApplicable {
		t.Fatalf("CopyGateState=%v, want %v", decision.CopyGateState, pipeline.CopyGateNotApplicable)
	}
	if decision.CopyGateReason != pipeline.CopyGateReasonTransportNonRawSplitConn {
		t.Fatalf("CopyGateReason=%v, want %v", decision.CopyGateReason, pipeline.CopyGateReasonTransportNonRawSplitConn)
	}
	if decision.CopyPath != pipeline.CopyPathNotApplicable {
		t.Fatalf("CopyPath=%v, want %v", decision.CopyPath, pipeline.CopyPathNotApplicable)
	}
}
