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
	args := []any{
		"proxy markers[kind=pipeline-summary]: ",
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
	}
	args = append(args,
		" splice_bytes=", snap.SpliceBytes,
		" splice_duration_ns=", snap.SpliceDurationNs,
		" userspace_bytes=", snap.UserspaceBytes,
		" userspace_duration_ns=", snap.UserspaceDurationNs,
		" userspace_exit=", snap.UserspaceExit,
		" sockmap_success=", snap.SockmapSuccess,
		" ktls_supported=", snap.Caps.KTLSSupported,
		" sockmap_supported=", snap.Caps.SockmapSupported,
		" splice_supported=", snap.Caps.SpliceSupported,
	)
	if snap.Target != "" {
		args = append(args, " target=", snap.Target)
	}
	if snap.LatencyVisibilityHint != "" {
		args = append(args, " latency_visibility_hint=", snap.LatencyVisibilityHint)
	}
	if snap.VisionSignalSource != "" {
		args = append(args,
			" vision_signal_source=", snap.VisionSignalSource,
			" vision_signal_wait_ns=", snap.VisionSignalWaitNs,
		)
		if snap.VisionLocalNoDetachWaitNs > 0 {
			args = append(args, " vision_local_no_detach_wait_ns=", snap.VisionLocalNoDetachWaitNs)
		}
	}
	if snap.AcceptToRequestParseNs > 0 {
		args = append(args, " accept_to_request_parse_ns=", snap.AcceptToRequestParseNs)
	}
	if snap.AcceptToVisionCommandNs > 0 {
		args = append(args, " accept_to_vision_command_ns=", snap.AcceptToVisionCommandNs)
	}
	if snap.PostDetachHandoffPath != "" || snap.PostDetachHandoffNs > 0 {
		args = append(args,
			" post_detach_handoff_path=", snap.PostDetachHandoffPath,
			" post_detach_handoff_ns=", snap.PostDetachHandoffNs,
		)
	}
	if snap.FlowTTFBNs > 0 {
		args = append(args, " flow_ttfb_ns=", snap.FlowTTFBNs)
	}
	if snap.TargetConnectNs > 0 {
		args = append(args, " target_connect_ns=", snap.TargetConnectNs)
	}
	if snap.VisionPreDetachNs > 0 {
		args = append(args, " vision_predetach_ns=", snap.VisionPreDetachNs)
	}
	if snap.TargetFirstByteNs > 0 {
		args = append(args, " target_first_byte_ns=", snap.TargetFirstByteNs)
	}
	if snap.DNSResolutionNs > 0 {
		args = append(args, " dns_resolution_ns=", snap.DNSResolutionNs)
	}
	if snap.UplinkUsefulDurationNs > 0 {
		args = append(args, " uplink_useful_duration_ns=", snap.UplinkUsefulDurationNs)
	}
	if snap.UplinkTotalDurationNs > 0 {
		args = append(args, " uplink_total_duration_ns=", snap.UplinkTotalDurationNs)
	}
	if snap.SockmapFallbackProbeNs > 0 {
		args = append(args, " sockmap_fallback_probe_ns=", snap.SockmapFallbackProbeNs)
	}
	errors.LogInfo(ctx, args...)
}
