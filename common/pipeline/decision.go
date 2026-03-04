package pipeline

// Path enumerates pipeline data-plane choices.
type Path string

const (
	PathUserspace Path = "userspace"
	PathSplice    Path = "splice"
	PathSockmap   Path = "sockmap"
	PathKTLS      Path = "ktls"
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
}
