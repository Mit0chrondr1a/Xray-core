package proxy

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/pipeline"
)

// logPipelineDecision emits a single structured marker for path selection.
// It is intentionally lightweight to avoid per-packet spam.
func logPipelineDecision(ctx context.Context, path string, reason string, caps pipeline.CapabilitySummary) {
	errors.LogInfo(ctx, "proxy markers[kind=pipeline-decision]: path=", path,
		" reason=", reason,
		" ktls_supported=", caps.KTLSSupported,
		" sockmap_supported=", caps.SockmapSupported,
		" splice_supported=", caps.SpliceSupported,
	)
}

// logPipelineSummary emits a one-shot per-connection summary at close.
func logPipelineSummary(ctx context.Context, snap pipeline.DecisionSnapshot) {
	kind := snap.Kind
	if kind == "" {
		kind = "proxy"
	}
	path := snap.Path
	errors.LogInfo(ctx, "proxy markers[kind=pipeline-summary]: ",
		"kind=", kind,
		" path=", string(path),
		" reason=", snap.Reason,
		" dns_flow_class=", snap.DNSFlowClass,
		" dns_plane=", snap.DNSPlane,
		" dns_guard_first_response_ns=", snap.DNSGuardFirstResponseNs,
		" dns_guard_zero_byte_timeout=", snap.DNSGuardZeroByteTimeout,
		" tls_offload_path=", snap.TLSOffloadPath,
		" copy_path=", snap.CopyPath,
		" copy_gate_state=", snap.CopyGateState,
		" copy_gate_reason=", snap.CopyGateReason,
		" splice_bytes=", snap.SpliceBytes,
		" splice_duration_ns=", snap.SpliceDurationNs,
		" userspace_bytes=", snap.UserspaceBytes,
		" userspace_duration_ns=", snap.UserspaceDurationNs,
		" sockmap_success=", snap.SockmapSuccess,
		" ktls_supported=", snap.Caps.KTLSSupported,
		" sockmap_supported=", snap.Caps.SockmapSupported,
		" splice_supported=", snap.Caps.SpliceSupported,
	)
}
