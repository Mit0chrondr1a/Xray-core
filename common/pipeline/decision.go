package pipeline

// Path enumerates pipeline data-plane choices.
type Path string

const (
	PathUserspace Path = "userspace"
	PathSplice    Path = "splice"
	PathSockmap   Path = "sockmap"
	PathKTLS      Path = "ktls"
)

// CopyPath enumerates copy-plane outcomes distinct from TLS offload.
type CopyPath string

const (
	CopyPathUnknown       CopyPath = ""
	CopyPathUserspace     CopyPath = "userspace_copy"
	CopyPathSplice        CopyPath = "splice"
	CopyPathSockmap       CopyPath = "sockmap"
	CopyPathNotApplicable CopyPath = "not_applicable"
)

// TLSOffloadPath reports whether TLS was offloaded.
type TLSOffloadPath string

const (
	TLSOffloadUnknown     TLSOffloadPath = ""
	TLSOffloadKTLS        TLSOffloadPath = "ktls"
	TLSOffloadUserspace   TLSOffloadPath = "userspace_tls"
	TLSOffloadNotRequired TLSOffloadPath = "not_required"
)

// CopyGateState enumerates gate states for copy-path eligibility.
type CopyGateState string

const (
	CopyGateUnset           CopyGateState = "copy_unset"
	CopyGateEligible        CopyGateState = "copy_eligible"
	CopyGatePendingDetach   CopyGateState = "copy_pending_detach"
	CopyGateForcedUserspace CopyGateState = "copy_forced_userspace"
	CopyGateNotApplicable   CopyGateState = "copy_not_applicable"
)

// CopyGateReason enumerates typed reasons for copy gating.
type CopyGateReason string

const (
	CopyGateReasonUnspecified              CopyGateReason = "unspecified"
	CopyGateReasonFlowNonVisionPolicy      CopyGateReason = "flow_nonvision_policy"
	CopyGateReasonTransportNonRawSplitConn CopyGateReason = "transport_nonraw_splitconn"
	CopyGateReasonTransportUserspace       CopyGateReason = "transport_userspace"
	CopyGateReasonVisionBypass             CopyGateReason = "vision_bypass"
	CopyGateReasonVisionNoDetach           CopyGateReason = "vision_no_detach"
	CopyGateReasonVisionControlCompat      CopyGateReason = "vision_control_compat"
	CopyGateReasonVisionUplinkComplete     CopyGateReason = "vision_uplink_complete"
	CopyGateReasonVisionCommandContinue    CopyGateReason = "vision_command_continue"
	CopyGateReasonDetachTimeout            CopyGateReason = "detach_timeout"
	CopyGateReasonSecurityGuard            CopyGateReason = "security_guard"
	CopyGateReasonMetadataMissing          CopyGateReason = "metadata_missing"
)

// UserspaceExit classifies how a userspace fallback path actually terminated.
// This complements the higher-level decision reason so logs can distinguish
// transport close causes from policy/gating causes.
type UserspaceExit string

const (
	UserspaceExitNone                   UserspaceExit = "none"
	UserspaceExitTimeout                UserspaceExit = "timeout"
	UserspaceExitRemoteReset            UserspaceExit = "remote_reset"
	UserspaceExitRemoteEOFNoResponse    UserspaceExit = "remote_eof_no_response"
	UserspaceExitLocalCloseNoResponse   UserspaceExit = "local_close_no_response"
	UserspaceExitStableUserspaceClose   UserspaceExit = "stable_userspace_close"
	UserspaceExitComplete               UserspaceExit = "complete"
	UserspaceExitPostDetachRetrySuccess UserspaceExit = "post_detach_retry_success"
)

// Canonical decision reasons. Keep centralized to avoid ad-hoc strings.
const (
	ReasonDefault                           = "default"
	ReasonSpliceCapabilityDisabled          = "splice_capability_disabled"
	ReasonDeferredTLSGuard                  = "deferred_tls_guard"
	ReasonUserspaceTLSGuard                 = "userspace_tls_guard"
	ReasonLoopbackUserspaceTLSGuard         = "loopback_userspace_tls_guard"
	ReasonSplicePrimary                     = "splice_primary"
	ReasonMissingInboundMetadata            = "missing_inbound_metadata"
	ReasonInboundForcedUserspace            = "inbound_forced_userspace"
	ReasonMissingOutboundMetadata           = "missing_outbound_metadata"
	ReasonOutboundForcedUserspace           = "outbound_forced_userspace"
	ReasonControlPlaneDNSGuard              = "control_plane_dns_guard"
	ReasonLoopbackDNSGuard                  = "loopback_dns_guard"
	ReasonLoopbackPairGuard                 = "loopback_pair_guard"
	ReasonEnsureRawFailed                   = "ensure_raw_failed"
	ReasonLoopbackTLSGuard                  = "loopback_tls_guard"
	ReasonSockmapCapabilityUnsupported      = "sockmap_capability_unsupported"
	ReasonSockmapManagerUnavailable         = "sockmap_mgr_unavailable"
	ReasonSockmapContention                 = "sockmap_contention"
	ReasonSockmapKTLSSockhashIncompatible   = "sockmap_ktls_sockhash_incompatible"
	ReasonSockmapUserspaceTLS               = "sockmap_userspace_tls"
	ReasonSockmapAsymmetricKTLS             = "sockmap_asymmetric_ktls"
	ReasonSockmapOtherPolicy                = "sockmap_other_policy"
	ReasonSockmapActive                     = "sockmap_active"
	ReasonSockmapWaitError                  = "sockmap_wait_error"
	ReasonSockmapWaitErrorUserspaceGuard    = "sockmap_wait_error_userspace_guard"
	ReasonForwardSuccess                    = "forward_success"
	ReasonSockmapWaitFallback               = "sockmap_wait_fallback"
	ReasonSockmapWaitFallbackUserspaceGuard = "sockmap_wait_fallback_userspace_guard"
	ReasonSockmapRegisterFail               = "sockmap_register_fail"
	ReasonVisionNoDetachPendingUserspace    = "vision_no_detach_pending_userspace"
	ReasonVisionNoDetachUserspace           = "vision_no_detach_userspace"
	ReasonVisionControlUserspace            = "vision_control_userspace"
	ReasonVisionUplinkCompleteUserspace     = "vision_uplink_complete_userspace"
	ReasonVisionQuiescedUserspace           = "vision_quiesced_userspace"
	ReasonVisionCommandContinueUserspace    = "vision_command_continue_userspace"
	ReasonUserspaceIdleTimeout              = "userspace_idle_timeout"
	ReasonUserspaceNoDetachIdleTimeout      = "userspace_no_detach_idle_timeout"
	ReasonUserspaceComplete                 = "userspace_complete"
	ReasonSplicePostSockmapStall            = "splice_post_sockmap_stall"
	ReasonKTLSPromotionCooldown             = "ktls_promotion_cooldown"
	ReasonFDExtractFailed                   = "fd_extract_failed"
	ReasonRustWrapFailedDrop                = "rust_wrap_failed_drop"
	ReasonKTLSPromoteFailedFallback         = "ktls_promote_failed_fallback"
	ReasonKTLSUnsupported                   = "ktls_unsupported"
	ReasonKTLSNotEnabled                    = "ktls_not_enabled"
	ReasonKTLSSuccess                       = "ktls_success"
	ReasonRustAuthFailed                    = "rust_auth_failed"
	ReasonRustPeekTimeout                   = "rust_peek_timeout"
	ReasonRustHandshakeFailed               = "rust_handshake_failed"
	ReasonFallbackFailed                    = "fallback_failed"
	ReasonFallbackSuccess                   = "fallback_success"
	ReasonUnexpectedDrop                    = "unexpected_drop"
	ReasonCopyNotApplicable                 = "copy_not_applicable"
)

// DecisionSnapshot carries per-connection pipeline outcomes for logging/telemetry.
type DecisionSnapshot struct {
	Path                Path
	Reason              string
	Caps                CapabilitySummary
	SpliceBytes         int64
	SpliceDurationNs    int64
	UserspaceBytes      int64
	UserspaceDurationNs int64
	SockmapSuccess      bool
	ErrorClass          string
	Kind                string // optional: component-specific tag (e.g., proxy, xhttp)
	// Telemetry planes
	TLSOffloadPath TLSOffloadPath
	CopyPath       CopyPath
	CopyGateState  CopyGateState
	CopyGateReason CopyGateReason
	// DNS control-plane telemetry.
	DNSFlowClass string
	DNSPlane     string
	// Guarded DNS telemetry.
	DNSGuardFirstResponseNs int64
	DNSGuardZeroByteTimeout bool
	UserspaceExit           UserspaceExit
}
