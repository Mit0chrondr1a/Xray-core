package proxy

import (
	"bytes"
	"context"
	gonet "net"
	"os"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/pipeline"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type VisionTransitionKind string

const (
	VisionTransitionKindOpaque       VisionTransitionKind = "opaque_conn"
	VisionTransitionKindCommonConn   VisionTransitionKind = "common_conn"
	VisionTransitionKindTLSConn      VisionTransitionKind = "tls_conn"
	VisionTransitionKindUTLSConn     VisionTransitionKind = "utls_conn"
	VisionTransitionKindRealityConn  VisionTransitionKind = "reality_conn"
	VisionTransitionKindRealityUConn VisionTransitionKind = "reality_uconn"
	VisionTransitionKindDeferredRust VisionTransitionKind = "deferred_rust_conn"
)

type VisionIngressOrigin string

const (
	VisionIngressOriginUnknown               VisionIngressOrigin = "unknown"
	VisionIngressOriginGoTLS                 VisionIngressOrigin = "go_tls"
	VisionIngressOriginGoReality             VisionIngressOrigin = "go_reality"
	VisionIngressOriginGoRealityFallback     VisionIngressOrigin = "go_reality_fallback"
	VisionIngressOriginNativeRealityDeferred VisionIngressOrigin = "native_reality_deferred"
)

type VisionTransitionSnapshot struct {
	Kind                            VisionTransitionKind
	IngressOrigin                   VisionIngressOrigin
	ScopeKey                        string
	PublicConnType                  string
	UsesDeferredRust                bool
	HasBufferedState                bool
	BufferedPlaintext               int
	BufferedRawAhead                int
	UplinkSemantic                  VisionSemantic
	DownlinkSemantic                VisionSemantic
	NativeProvisionalSemantic       VisionNativeProvisionalSemantic
	NativeProvisionalSource         VisionNativeProvisionalSemanticSource
	NativeProvisionalObserved       VisionNativeProvisionalSemantic
	NativeProvisionalObservedSource VisionNativeProvisionalSemanticSource
	NativeProvisionalOutcome        VisionNativeProvisionalOutcome
	NativeProvisionalOutcomeSource  VisionNativeProvisionalOutcomeSource
	NativeProvisionalTerminalReason VisionNativeProvisionalTerminalReason
	DrainMode                       VisionDrainMode
	DrainCount                      int32
	DrainPlaintext                  int
	DrainRawAhead                   int
	TransportDrainMode              VisionDrainMode
	TransportDrainCount             int32
	TransportDrainPlaintext         int
	TransportDrainRawAhead          int
	DrainRelation                   VisionDrainRelation
	BridgeAssessment                VisionBridgeAssessment
	PendingQuality                  VisionPendingQuality
	PendingClass                    VisionPendingClass
	PendingGap                      VisionPendingGap
	TransportReadOps                int32
	TransportReadBytes              int
	TransportWriteOps               int32
	TransportWriteBytes             int
	TransportProgress               VisionTransportProgressProfile
	TransportLifecycleState         VisionTransportLifecycleState
	TransportDetachStatus           VisionTransportDetachStatus
	TransportKTLSPromotion          VisionTransportKTLSPromotion
}

type VisionTransitionEvent string

const (
	VisionTransitionEventCommandObserved VisionTransitionEvent = "command_observed"
	VisionTransitionEventPayloadBypass   VisionTransitionEvent = "payload_bypass"
)

type VisionDrainMode string

const (
	VisionDrainModeNone     VisionDrainMode = "none"
	VisionDrainModeBuffered VisionDrainMode = "buffered_drain"
	VisionDrainModeDeferred VisionDrainMode = "deferred_detach"
	VisionDrainModeMixed    VisionDrainMode = "mixed"
)

type VisionSemantic string

const (
	VisionSemanticUnknown          VisionSemantic = "unknown"
	VisionSemanticPayloadBypass    VisionSemantic = "payload_bypass"
	VisionSemanticExplicitNoDetach VisionSemantic = "explicit_no_detach"
	VisionSemanticExplicitDirect   VisionSemantic = "explicit_direct_copy"
)

type VisionTransportLifecycleState string

const (
	VisionTransportLifecycleUnknown        VisionTransportLifecycleState = "unknown"
	VisionTransportLifecycleDeferredActive VisionTransportLifecycleState = "deferred_active"
	VisionTransportLifecycleDeferredDetach VisionTransportLifecycleState = "deferred_detached"
	VisionTransportLifecycleKTLSEnabled    VisionTransportLifecycleState = "ktls_enabled"
)

type VisionTransportDetachStatus string

const (
	VisionTransportDetachStatusNone      VisionTransportDetachStatus = "none"
	VisionTransportDetachStatusCompleted VisionTransportDetachStatus = "completed"
	VisionTransportDetachStatusFailed    VisionTransportDetachStatus = "failed"
	VisionTransportDetachStatusMixed     VisionTransportDetachStatus = "mixed"
)

type VisionTransportKTLSPromotion string

const (
	VisionTransportKTLSPromotionNone        VisionTransportKTLSPromotion = "none"
	VisionTransportKTLSPromotionEnabled     VisionTransportKTLSPromotion = "enabled"
	VisionTransportKTLSPromotionCooldown    VisionTransportKTLSPromotion = "cooldown"
	VisionTransportKTLSPromotionUnsupported VisionTransportKTLSPromotion = "unsupported"
	VisionTransportKTLSPromotionFailed      VisionTransportKTLSPromotion = "failed"
	VisionTransportKTLSPromotionMixed       VisionTransportKTLSPromotion = "mixed"
)

type VisionTransportProgressProfile string

const (
	VisionTransportProgressNone          VisionTransportProgressProfile = "none"
	VisionTransportProgressWriteOnly     VisionTransportProgressProfile = "write_only"
	VisionTransportProgressReadOnly      VisionTransportProgressProfile = "read_only"
	VisionTransportProgressBidirectional VisionTransportProgressProfile = "bidirectional"
)

type VisionDrainRelation string

const (
	VisionDrainRelationNone          VisionDrainRelation = "none"
	VisionDrainRelationAcceptedOnly  VisionDrainRelation = "accepted_only"
	VisionDrainRelationTransportOnly VisionDrainRelation = "transport_only"
	VisionDrainRelationAligned       VisionDrainRelation = "aligned"
	VisionDrainRelationMismatch      VisionDrainRelation = "mismatch"
)

type VisionBridgeAssessment string

const (
	VisionBridgeAssessmentNone               VisionBridgeAssessment = "none"
	VisionBridgeAssessmentGoBaseline         VisionBridgeAssessment = "go_baseline"
	VisionBridgeAssessmentNativePending      VisionBridgeAssessment = "native_pending"
	VisionBridgeAssessmentNativeAligned      VisionBridgeAssessment = "native_aligned"
	VisionBridgeAssessmentNativeDivergent    VisionBridgeAssessment = "native_divergent"
	VisionBridgeAssessmentNativeDetachFailed VisionBridgeAssessment = "native_detach_failed"
)

type VisionPendingQuality string

const (
	VisionPendingQualityNone    VisionPendingQuality = "none"
	VisionPendingQualityBenign  VisionPendingQuality = "benign"
	VisionPendingQualityFailure VisionPendingQuality = "user_visible_failure"
)

type VisionPendingClass string

const (
	VisionPendingClassNone             VisionPendingClass = "none"
	VisionPendingClassCommand0Only     VisionPendingClass = "command0_only"
	VisionPendingClassExplicitNoDetach VisionPendingClass = "explicit_no_detach"
	VisionPendingClassPayloadBypass    VisionPendingClass = "payload_bypass"
	VisionPendingClassOther            VisionPendingClass = "other"
)

type VisionPendingGap string

const (
	VisionPendingGapNone                       VisionPendingGap = "none"
	VisionPendingGapCommand0BidirectionalNoDet VisionPendingGap = "command0_bidirectional_no_detach"
	VisionPendingGapOther                      VisionPendingGap = "other"
)

type VisionNativeProvisionalSemantic string

const (
	VisionNativeProvisionalSemanticNone                  VisionNativeProvisionalSemantic = "none"
	VisionNativeProvisionalSemanticCommand0Bidirectional VisionNativeProvisionalSemantic = "command0_bidirectional"
)

type VisionNativeProvisionalSemanticSource string

const (
	VisionNativeProvisionalSemanticSourceNone              VisionNativeProvisionalSemanticSource = "none"
	VisionNativeProvisionalSemanticSourceDerived           VisionNativeProvisionalSemanticSource = "derived"
	VisionNativeProvisionalSemanticSourceTransportProducer VisionNativeProvisionalSemanticSource = "transport_producer"
	VisionNativeProvisionalSemanticSourceBridgeProducer    VisionNativeProvisionalSemanticSource = "bridge_producer"
	VisionNativeProvisionalSemanticSourceExplicitProducer  VisionNativeProvisionalSemanticSource = "explicit_producer"
	// Deprecated alias kept for compatibility with older bridge-oriented tests and logs.
	VisionNativeProvisionalSemanticSourceSemanticProducer VisionNativeProvisionalSemanticSource = VisionNativeProvisionalSemanticSourceBridgeProducer
)

type VisionNativeProvisionalOutcome string

const (
	VisionNativeProvisionalOutcomeNone              VisionNativeProvisionalOutcome = "none"
	VisionNativeProvisionalOutcomeActive            VisionNativeProvisionalOutcome = "active"
	VisionNativeProvisionalOutcomeTerminatedPending VisionNativeProvisionalOutcome = "terminated_pending"
	VisionNativeProvisionalOutcomeResolvedDirect    VisionNativeProvisionalOutcome = "resolved_direct_copy"
	VisionNativeProvisionalOutcomeResolvedNoDetach  VisionNativeProvisionalOutcome = "resolved_no_detach"
	VisionNativeProvisionalOutcomeBenignClose       VisionNativeProvisionalOutcome = "benign_pending_close"
	VisionNativeProvisionalOutcomeFailedPending     VisionNativeProvisionalOutcome = "failed_pending"
)

type VisionNativeProvisionalTerminalReason string

const (
	VisionNativeProvisionalTerminalReasonNone       VisionNativeProvisionalTerminalReason = "none"
	VisionNativeProvisionalTerminalReasonLocalClose VisionNativeProvisionalTerminalReason = "local_close"
	VisionNativeProvisionalTerminalReasonEOF        VisionNativeProvisionalTerminalReason = "eof"
	VisionNativeProvisionalTerminalReasonClosed     VisionNativeProvisionalTerminalReason = "closed"
	VisionNativeProvisionalTerminalReasonReset      VisionNativeProvisionalTerminalReason = "reset"
	VisionNativeProvisionalTerminalReasonBrokenPipe VisionNativeProvisionalTerminalReason = "broken_pipe"
	VisionNativeProvisionalTerminalReasonBadMessage VisionNativeProvisionalTerminalReason = "bad_message"
	VisionNativeProvisionalTerminalReasonEIO        VisionNativeProvisionalTerminalReason = "eio"
	VisionNativeProvisionalTerminalReasonOther      VisionNativeProvisionalTerminalReason = "other"
)

type VisionNativeProvisionalOutcomeSource string

const (
	VisionNativeProvisionalOutcomeSourceNone              VisionNativeProvisionalOutcomeSource = "none"
	VisionNativeProvisionalOutcomeSourceDerived           VisionNativeProvisionalOutcomeSource = "derived"
	VisionNativeProvisionalOutcomeSourceTransportProducer VisionNativeProvisionalOutcomeSource = "transport_producer"
	VisionNativeProvisionalOutcomeSourceBridgeProducer    VisionNativeProvisionalOutcomeSource = "bridge_producer"
	VisionNativeProvisionalOutcomeSourceExplicitProducer  VisionNativeProvisionalOutcomeSource = "explicit_producer"
	// Deprecated alias kept for compatibility with older bridge-oriented tests and logs.
	VisionNativeProvisionalOutcomeSourceSemanticProducer VisionNativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceBridgeProducer
)

// VisionTransitionSource makes the pre-detach Vision transition contract explicit.
//
// Historically Vision reached into Go TLS/REALITY internals via reflection to
// access input/rawInput. Native deferred REALITY does not expose those fields,
// so the long-term seam needs to be explicit rather than spread across call
// sites. This type preserves current behavior while centralizing that contract.
type VisionTransitionSource struct {
	conn     gonet.Conn
	input    *bytes.Reader
	rawInput *bytes.Buffer
	kind     VisionTransitionKind
	origin   VisionIngressOrigin
}

var visionTransitionTraceByConn sync.Map
var visionBridgeAssessmentStatsByScope sync.Map
var visionBridgeProbeEpochByScope sync.Map
var visionBridgeAssessmentNowFn = time.Now
var visionBridgeProbeNowFn = time.Now
var visionBridgeAssessmentBucketWidth = time.Minute

const (
	visionBridgeAssessmentUnscopedKey = "__unscoped__"
	visionBridgeAssessmentBucketCount = 10
)

type visionBridgeAssessmentWindow struct {
	mu                                            sync.Mutex
	startBucket                                   int64
	goBaseline                                    [visionBridgeAssessmentBucketCount]uint64
	nativePending                                 [visionBridgeAssessmentBucketCount]uint64
	nativePendingBenign                           [visionBridgeAssessmentBucketCount]uint64
	nativePendingFailure                          [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalCommand0Bidirectional        [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalCommand0BidirectionalFailure [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalActive                       [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalTerminatedPending            [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalResolvedDirect               [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalResolvedNoDetach             [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalBenignClose                  [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPending                [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPendingLocalClose      [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPendingEOF             [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPendingClosed          [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPendingReset           [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPendingBrokenPipe      [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPendingBadMessage      [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPendingEIO             [visionBridgeAssessmentBucketCount]uint64
	nativeProvisionalFailedPendingOther           [visionBridgeAssessmentBucketCount]uint64
	nativePendingCommand0Failure                  [visionBridgeAssessmentBucketCount]uint64
	nativePendingCommand0BidirectionalFailure     [visionBridgeAssessmentBucketCount]uint64
	nativeAligned                                 [visionBridgeAssessmentBucketCount]uint64
	nativeDivergent                               [visionBridgeAssessmentBucketCount]uint64
	nativeDetachFailed                            [visionBridgeAssessmentBucketCount]uint64
}

type visionBridgeProbeEpoch struct {
	mu       sync.Mutex
	scopeKey string
	state    VisionBridgeProbeState
	verdict  VisionBridgeProbeVerdict
	started  time.Time
	deadline time.Time
	budget   uint64
	stats    VisionBridgeAssessmentStats
}

type VisionTransitionDirectionSummary struct {
	Command0Count int32
	Command1Count int32
	Command2Count int32
	PayloadBypass bool
	Semantic      VisionSemantic
}

type VisionTransitionSummary struct {
	Kind                            VisionTransitionKind
	IngressOrigin                   VisionIngressOrigin
	ScopeKey                        string
	Uplink                          VisionTransitionDirectionSummary
	Downlink                        VisionTransitionDirectionSummary
	NativeProvisionalSemantic       VisionNativeProvisionalSemantic
	NativeProvisionalSource         VisionNativeProvisionalSemanticSource
	NativeProvisionalObserved       VisionNativeProvisionalSemantic
	NativeProvisionalObservedSource VisionNativeProvisionalSemanticSource
	NativeProvisionalOutcome        VisionNativeProvisionalOutcome
	NativeProvisionalOutcomeSource  VisionNativeProvisionalOutcomeSource
	NativeProvisionalTerminalReason VisionNativeProvisionalTerminalReason
	DrainMode                       VisionDrainMode
	DrainCount                      int32
	DrainPlaintextBytes             int
	DrainRawAheadBytes              int
	TransportDrainMode              VisionDrainMode
	TransportDrainCount             int32
	TransportDrainPlaintextLen      int
	TransportDrainRawAheadLen       int
	DrainRelation                   VisionDrainRelation
	BridgeAssessment                VisionBridgeAssessment
	PendingQuality                  VisionPendingQuality
	PendingClass                    VisionPendingClass
	PendingGap                      VisionPendingGap
	TransportReadOps                int32
	TransportReadBytes              int
	TransportWriteOps               int32
	TransportWriteBytes             int
	TransportProgress               VisionTransportProgressProfile
	TransportLifecycleState         VisionTransportLifecycleState
	TransportDetachStatus           VisionTransportDetachStatus
	TransportKTLSPromotion          VisionTransportKTLSPromotion
}

type VisionBridgeAssessmentStats struct {
	GoBaseline                                    uint64
	NativePending                                 uint64
	NativePendingBenign                           uint64
	NativePendingFailure                          uint64
	NativeProvisionalCommand0Bidirectional        uint64
	NativeProvisionalCommand0BidirectionalFailure uint64
	NativeProvisionalActive                       uint64
	NativeProvisionalTerminatedPending            uint64
	NativeProvisionalResolvedDirect               uint64
	NativeProvisionalResolvedNoDetach             uint64
	NativeProvisionalBenignClose                  uint64
	NativeProvisionalFailedPending                uint64
	NativeProvisionalFailedPendingLocalClose      uint64
	NativeProvisionalFailedPendingEOF             uint64
	NativeProvisionalFailedPendingClosed          uint64
	NativeProvisionalFailedPendingReset           uint64
	NativeProvisionalFailedPendingBrokenPipe      uint64
	NativeProvisionalFailedPendingBadMessage      uint64
	NativeProvisionalFailedPendingEIO             uint64
	NativeProvisionalFailedPendingOther           uint64
	NativePendingCommand0Failure                  uint64
	NativePendingCommand0BidirectionalFailure     uint64
	NativeAligned                                 uint64
	NativeDivergent                               uint64
	NativeDetachFailed                            uint64
}

type VisionBridgeProbeState string

const (
	VisionBridgeProbeStateInactive  VisionBridgeProbeState = "inactive"
	VisionBridgeProbeStateActive    VisionBridgeProbeState = "active"
	VisionBridgeProbeStateCompleted VisionBridgeProbeState = "completed"
)

type VisionBridgeProbeVerdict string

const (
	VisionBridgeProbeVerdictNone                                     VisionBridgeProbeVerdict = "none"
	VisionBridgeProbeVerdictNoSignal                                 VisionBridgeProbeVerdict = "no_signal"
	VisionBridgeProbeVerdictGoBaseline                               VisionBridgeProbeVerdict = "go_baseline"
	VisionBridgeProbeVerdictNativeAligned                            VisionBridgeProbeVerdict = "native_aligned"
	VisionBridgeProbeVerdictNativePendingBenign                      VisionBridgeProbeVerdict = "native_pending_benign"
	VisionBridgeProbeVerdictNativePendingFailure                     VisionBridgeProbeVerdict = "native_pending_failure"
	VisionBridgeProbeVerdictNativeProvisionalFailedPendingLocalClose VisionBridgeProbeVerdict = "native_provisional_failed_pending_local_close"
	VisionBridgeProbeVerdictNativeProvisionalFailedPending           VisionBridgeProbeVerdict = "native_provisional_failed_pending"
	VisionBridgeProbeVerdictNativeProvisionalCommand0Bidirectional   VisionBridgeProbeVerdict = "native_provisional_command0_bidirectional_failure"
	VisionBridgeProbeVerdictNativePendingCommand0                    VisionBridgeProbeVerdict = "native_pending_command0_failure"
	VisionBridgeProbeVerdictNativePendingCommand0Bidirectional       VisionBridgeProbeVerdict = "native_pending_command0_bidirectional_failure"
	VisionBridgeProbeVerdictNativeDivergent                          VisionBridgeProbeVerdict = "native_divergent"
	VisionBridgeProbeVerdictNativeDetachFailed                       VisionBridgeProbeVerdict = "native_detach_failed"
)

type VisionBridgeProbeSnapshot struct {
	ScopeKey            string
	State               VisionBridgeProbeState
	Verdict             VisionBridgeProbeVerdict
	FailedPendingReason VisionNativeProvisionalTerminalReason
	Budget              uint64
	Observed            uint64
	StartedAt           time.Time
	Deadline            time.Time
	Remaining           time.Duration
	Stats               VisionBridgeAssessmentStats
}

func newVisionTransitionSummary() *VisionTransitionSummary {
	return &VisionTransitionSummary{
		ScopeKey: normalizeVisionBridgeAssessmentScope(""),
		Uplink: VisionTransitionDirectionSummary{
			Semantic: VisionSemanticUnknown,
		},
		Downlink: VisionTransitionDirectionSummary{
			Semantic: VisionSemanticUnknown,
		},
		NativeProvisionalSemantic:       VisionNativeProvisionalSemanticNone,
		NativeProvisionalSource:         VisionNativeProvisionalSemanticSourceNone,
		NativeProvisionalObserved:       VisionNativeProvisionalSemanticNone,
		NativeProvisionalObservedSource: VisionNativeProvisionalSemanticSourceNone,
		NativeProvisionalOutcome:        VisionNativeProvisionalOutcomeNone,
		NativeProvisionalOutcomeSource:  VisionNativeProvisionalOutcomeSourceNone,
		NativeProvisionalTerminalReason: VisionNativeProvisionalTerminalReasonNone,
		DrainMode:                       VisionDrainModeNone,
		TransportDrainMode:              VisionDrainModeNone,
		DrainRelation:                   VisionDrainRelationNone,
		BridgeAssessment:                VisionBridgeAssessmentNone,
		PendingQuality:                  VisionPendingQualityNone,
		PendingClass:                    VisionPendingClassNone,
		PendingGap:                      VisionPendingGapNone,
		TransportProgress:               VisionTransportProgressNone,
		TransportLifecycleState:         VisionTransportLifecycleUnknown,
		TransportDetachStatus:           VisionTransportDetachStatusNone,
		TransportKTLSPromotion:          VisionTransportKTLSPromotionNone,
	}
}

func init() {
	tls.SetDeferredRustDrainObserver(observeVisionTransportDeferredDrain)
	tls.SetDeferredRustLifecycleObserver(observeVisionTransportLifecycleEvent)
	tls.SetDeferredRustProgressObserver(observeVisionTransportProgressEvent)
	tls.SetDeferredRustProvisionalObserver(observeVisionTransportProvisionalEvent)
}

func NewVisionTransitionSource(conn gonet.Conn, input *bytes.Reader, rawInput *bytes.Buffer) *VisionTransitionSource {
	return &VisionTransitionSource{
		conn:     conn,
		input:    input,
		rawInput: rawInput,
		kind:     VisionTransitionKindOpaque,
	}
}

func (s *VisionTransitionSource) Conn() gonet.Conn {
	if s == nil {
		return nil
	}
	return s.conn
}

func (s *VisionTransitionSource) UsesDeferredRustConn() bool {
	if s == nil {
		return false
	}
	return unwrapVisionDeferredConn(s.conn) != nil
}

func (s *VisionTransitionSource) Kind() VisionTransitionKind {
	if s == nil {
		return VisionTransitionKindOpaque
	}
	return s.kind
}

func (s *VisionTransitionSource) Snapshot() VisionTransitionSnapshot {
	snap := VisionTransitionSnapshot{
		Kind:                            s.Kind(),
		IngressOrigin:                   VisionIngressOriginUnknown,
		UplinkSemantic:                  VisionSemanticUnknown,
		DownlinkSemantic:                VisionSemanticUnknown,
		NativeProvisionalSource:         VisionNativeProvisionalSemanticSourceNone,
		NativeProvisionalObservedSource: VisionNativeProvisionalSemanticSourceNone,
		NativeProvisionalOutcome:        VisionNativeProvisionalOutcomeNone,
		NativeProvisionalOutcomeSource:  VisionNativeProvisionalOutcomeSourceNone,
		NativeProvisionalTerminalReason: VisionNativeProvisionalTerminalReasonNone,
		DrainMode:                       VisionDrainModeNone,
		TransportDrainMode:              VisionDrainModeNone,
		DrainRelation:                   VisionDrainRelationNone,
		BridgeAssessment:                VisionBridgeAssessmentNone,
		PendingClass:                    VisionPendingClassNone,
		PendingGap:                      VisionPendingGapNone,
		TransportLifecycleState:         VisionTransportLifecycleUnknown,
		TransportDetachStatus:           VisionTransportDetachStatusNone,
		TransportKTLSPromotion:          VisionTransportKTLSPromotionNone,
	}
	if s == nil {
		return snap
	}
	snap.IngressOrigin = s.origin
	if s.conn != nil {
		snap.PublicConnType = reflect.TypeOf(s.conn).String()
	}
	snap.UsesDeferredRust = s.UsesDeferredRustConn()
	if s.input != nil {
		snap.HasBufferedState = true
		snap.BufferedPlaintext = s.input.Len()
	}
	if s.rawInput != nil {
		snap.HasBufferedState = true
		snap.BufferedRawAhead = s.rawInput.Len()
	}
	if summary, ok := SnapshotVisionTransitionSummary(s.conn, nil); ok {
		snap.ScopeKey = summary.ScopeKey
		snap.UplinkSemantic = summary.Uplink.Semantic
		snap.DownlinkSemantic = summary.Downlink.Semantic
		snap.NativeProvisionalSemantic = summary.NativeProvisionalSemantic
		snap.NativeProvisionalSource = summary.NativeProvisionalSource
		snap.NativeProvisionalObserved = summary.NativeProvisionalObserved
		snap.NativeProvisionalObservedSource = summary.NativeProvisionalObservedSource
		snap.NativeProvisionalOutcome = summary.NativeProvisionalOutcome
		snap.NativeProvisionalOutcomeSource = summary.NativeProvisionalOutcomeSource
		snap.NativeProvisionalTerminalReason = summary.NativeProvisionalTerminalReason
		snap.DrainMode = summary.DrainMode
		snap.DrainCount = summary.DrainCount
		snap.DrainPlaintext = summary.DrainPlaintextBytes
		snap.DrainRawAhead = summary.DrainRawAheadBytes
		snap.TransportDrainMode = summary.TransportDrainMode
		snap.TransportDrainCount = summary.TransportDrainCount
		snap.TransportDrainPlaintext = summary.TransportDrainPlaintextLen
		snap.TransportDrainRawAhead = summary.TransportDrainRawAheadLen
		snap.DrainRelation = summary.DrainRelation
		snap.BridgeAssessment = summary.BridgeAssessment
		snap.PendingQuality = summary.PendingQuality
		snap.PendingClass = summary.PendingClass
		snap.PendingGap = summary.PendingGap
		snap.TransportReadOps = summary.TransportReadOps
		snap.TransportReadBytes = summary.TransportReadBytes
		snap.TransportWriteOps = summary.TransportWriteOps
		snap.TransportWriteBytes = summary.TransportWriteBytes
		snap.TransportProgress = summary.TransportProgress
		snap.TransportLifecycleState = summary.TransportLifecycleState
		snap.TransportDetachStatus = summary.TransportDetachStatus
		snap.TransportKTLSPromotion = summary.TransportKTLSPromotion
	}
	return snap
}

func (s *VisionTransitionSource) DrainBufferedState() (plaintext []byte, rawAhead []byte) {
	if s == nil {
		return nil, nil
	}
	if s.input != nil {
		if data, err := buf.ReadAllToBytes(s.input); err == nil && len(data) > 0 {
			plaintext = data
		}
		*s.input = bytes.Reader{}
		s.input = nil
	}
	if s.rawInput != nil {
		if data, err := buf.ReadAllToBytes(s.rawInput); err == nil && len(data) > 0 {
			rawAhead = data
		}
		*s.rawInput = bytes.Buffer{}
		s.rawInput = nil
	}
	return plaintext, rawAhead
}

func debugVisionTransitionTrace() bool {
	return os.Getenv("XRAY_DEBUG_VISION_TRANSITION_TRACE") == "1"
}

func LogVisionTransitionSource(ctx context.Context, direction string, source *VisionTransitionSource) {
	if source == nil {
		return
	}
	ObserveVisionTransitionSource(source.conn, source.Kind(), source.origin)
	if !debugVisionTransitionTrace() {
		return
	}
	snap := source.Snapshot()
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-source]: ",
		"direction=", direction,
		" transition_kind=", snap.Kind,
		" ingress_origin=", snap.IngressOrigin,
		" bridge_scope=", snap.ScopeKey,
		" public_conn_type=", snap.PublicConnType,
		" uses_deferred_rust=", snap.UsesDeferredRust,
		" has_buffered_state=", snap.HasBufferedState,
		" buffered_plaintext=", snap.BufferedPlaintext,
		" buffered_raw_ahead=", snap.BufferedRawAhead,
	)
}

func LogVisionTransitionDrain(ctx context.Context, direction string, source *VisionTransitionSource, plaintextLen int, rawAheadLen int) {
	if source == nil {
		return
	}
	TraceVisionTransitionDrain(ctx, direction, source, plaintextLen, rawAheadLen)
}

// TraceVisionTransitionDrain emits the debug drain marker without mutating
// bridge state. Callers that already observed drain facts explicitly should use
// this helper to avoid double-counting bridge summaries.
func TraceVisionTransitionDrain(ctx context.Context, direction string, source *VisionTransitionSource, plaintextLen int, rawAheadLen int) {
	if source == nil {
		return
	}
	if !debugVisionTransitionTrace() {
		return
	}
	snap := source.Snapshot()
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-drain]: ",
		"direction=", direction,
		" transition_kind=", snap.Kind,
		" ingress_origin=", snap.IngressOrigin,
		" bridge_scope=", snap.ScopeKey,
		" uses_deferred_rust=", snap.UsesDeferredRust,
		" plaintext_len=", plaintextLen,
		" raw_ahead_len=", rawAheadLen,
	)
}

func LogVisionTransitionEvent(ctx context.Context, direction string, source *VisionTransitionSource, event VisionTransitionEvent, command int, continueCount int32, remainingContent int32, remainingPadding int32, withinPadding bool, switchToDirectCopy bool) {
	if source == nil {
		return
	}
	ObserveVisionTransitionEvent(source.conn, source.Kind(), source.origin, direction, event, command)
	if !debugVisionTransitionTrace() {
		return
	}
	snap := source.Snapshot()
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-event]: ",
		"direction=", direction,
		" transition_kind=", snap.Kind,
		" ingress_origin=", snap.IngressOrigin,
		" bridge_scope=", snap.ScopeKey,
		" event=", event,
		" command=", command,
		" continue_count=", continueCount,
		" remaining_content=", remainingContent,
		" remaining_padding=", remainingPadding,
		" within_padding=", withinPadding,
		" switch_to_direct_copy=", switchToDirectCopy,
	)
}

func LogVisionTransitionSummary(ctx context.Context, primaryConn gonet.Conn, secondaryConn gonet.Conn, snap *pipeline.DecisionSnapshot) {
	publishVisionBridgeOwnedLocalTerminalOutcome(primaryConn, snap)
	if secondaryConn != nil && secondaryConn != primaryConn {
		publishVisionBridgeOwnedLocalTerminalOutcome(secondaryConn, snap)
	}
	summary, ok := consumeVisionTransitionSummary(primaryConn, secondaryConn)
	if !ok {
		return
	}
	finalizeVisionTransitionSummary(&summary, snap)
	observeVisionBridgeAssessment(
		summary.ScopeKey,
		summary.BridgeAssessment,
		summary.PendingQuality,
		summary.PendingClass,
		summary.PendingGap,
		summary.NativeProvisionalObserved,
		summary.NativeProvisionalObservedSource,
		summary.NativeProvisionalOutcome,
		summary.NativeProvisionalOutcomeSource,
		summary.NativeProvisionalTerminalReason,
	)
	if !debugVisionTransitionTrace() {
		return
	}
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-summary]: ",
		" transition_kind=", summary.Kind,
		" ingress_origin=", summary.IngressOrigin,
		" bridge_scope=", summary.ScopeKey,
		" uplink_command0_count=", summary.Uplink.Command0Count,
		" uplink_command1_count=", summary.Uplink.Command1Count,
		" uplink_command2_count=", summary.Uplink.Command2Count,
		" uplink_payload_bypass=", summary.Uplink.PayloadBypass,
		" uplink_semantic=", summary.Uplink.Semantic,
		" downlink_command0_count=", summary.Downlink.Command0Count,
		" downlink_command1_count=", summary.Downlink.Command1Count,
		" downlink_command2_count=", summary.Downlink.Command2Count,
		" downlink_payload_bypass=", summary.Downlink.PayloadBypass,
		" downlink_semantic=", summary.Downlink.Semantic,
		" native_provisional_semantic=", summary.NativeProvisionalSemantic,
		" native_provisional_source=", summary.NativeProvisionalSource,
		" native_provisional_observed=", summary.NativeProvisionalObserved,
		" native_provisional_observed_source=", summary.NativeProvisionalObservedSource,
		" native_provisional_outcome=", summary.NativeProvisionalOutcome,
		" native_provisional_outcome_source=", summary.NativeProvisionalOutcomeSource,
		" native_provisional_terminal_reason=", summary.NativeProvisionalTerminalReason,
		" drain_mode=", summary.DrainMode,
		" drain_count=", summary.DrainCount,
		" drain_plaintext_bytes=", summary.DrainPlaintextBytes,
		" drain_raw_ahead_bytes=", summary.DrainRawAheadBytes,
		" transport_drain_mode=", summary.TransportDrainMode,
		" transport_drain_count=", summary.TransportDrainCount,
		" transport_drain_plaintext_bytes=", summary.TransportDrainPlaintextLen,
		" transport_drain_raw_ahead_bytes=", summary.TransportDrainRawAheadLen,
		" drain_relation=", summary.DrainRelation,
		" bridge_assessment=", summary.BridgeAssessment,
		" pending_quality=", summary.PendingQuality,
		" pending_class=", summary.PendingClass,
		" pending_gap=", summary.PendingGap,
		" transport_read_ops=", summary.TransportReadOps,
		" transport_read_bytes=", summary.TransportReadBytes,
		" transport_write_ops=", summary.TransportWriteOps,
		" transport_write_bytes=", summary.TransportWriteBytes,
		" transport_progress=", summary.TransportProgress,
		" transport_lifecycle_state=", summary.TransportLifecycleState,
		" transport_detach_status=", summary.TransportDetachStatus,
		" transport_ktls_promotion=", summary.TransportKTLSPromotion,
	)
}

func publishVisionBridgeOwnedLocalTerminalOutcome(conn gonet.Conn, snap *pipeline.DecisionSnapshot) {
	if conn == nil || snap == nil {
		return
	}
	summary, ok := snapshotVisionTransitionSummaryForConn(conn, 0)
	if !ok {
		return
	}
	if summary.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		return
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional ||
		!isVisionNativeProvisionalProducerSource(summary.NativeProvisionalObservedSource) {
		return
	}
	switch summary.NativeProvisionalOutcome {
	case VisionNativeProvisionalOutcomeResolvedDirect,
		VisionNativeProvisionalOutcomeResolvedNoDetach,
		VisionNativeProvisionalOutcomeTerminatedPending:
		return
	}
	pendingQuality := deriveVisionPendingQuality(summary, snap)
	terminalReason := deriveVisionPendingTerminalReasonFromDecision(snap, pendingQuality)
	if terminalReason != VisionNativeProvisionalTerminalReasonLocalClose {
		return
	}
	switch pendingQuality {
	case VisionPendingQualityFailure:
		ObserveVisionNativeProvisionalOutcome(conn, summary.Kind, summary.IngressOrigin, VisionNativeProvisionalOutcomeFailedPending)
		ObserveVisionNativeProvisionalTerminalReason(conn, summary.Kind, summary.IngressOrigin, VisionNativeProvisionalTerminalReasonLocalClose)
	case VisionPendingQualityBenign:
		ObserveVisionNativeProvisionalOutcome(conn, summary.Kind, summary.IngressOrigin, VisionNativeProvisionalOutcomeBenignClose)
		ObserveVisionNativeProvisionalTerminalReason(conn, summary.Kind, summary.IngressOrigin, VisionNativeProvisionalTerminalReasonLocalClose)
	}
}

// ObserveVisionTransitionSource records the runtime bridge state for a seam
// producer without requiring a VisionTransitionSource wrapper or debug logging.
//
// This is the producer-grade API that future native bridge code should target.
func ObserveVisionTransitionSource(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	refreshVisionRuntimeDerivedFields(summary)
}

func ObserveVisionTransitionScope(conn gonet.Conn, scope string) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	scope = normalizeVisionBridgeAssessmentScope(scope)
	if summary.ScopeKey == "" || summary.ScopeKey == visionBridgeAssessmentUnscopedKey {
		summary.ScopeKey = scope
	}
	refreshVisionRuntimeDerivedFields(summary)
}

// ObserveVisionTransitionEvent records semantic progression for a seam producer
// without requiring debug logging or a VisionTransitionSource wrapper.
func ObserveVisionTransitionEvent(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, direction string, event VisionTransitionEvent, command int) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	trace := &summary.Downlink
	if direction == "uplink" {
		trace = &summary.Uplink
	}
	switch event {
	case VisionTransitionEventPayloadBypass:
		trace.PayloadBypass = true
		trace.Semantic = mergeVisionSemantic(trace.Semantic, VisionSemanticPayloadBypass)
	case VisionTransitionEventCommandObserved:
		switch command {
		case 0:
			trace.Command0Count++
		case 1:
			trace.Command1Count++
			trace.Semantic = mergeVisionSemantic(trace.Semantic, VisionSemanticExplicitNoDetach)
		case 2:
			trace.Command2Count++
			trace.Semantic = mergeVisionSemantic(trace.Semantic, VisionSemanticExplicitDirect)
		}
	}
	refreshVisionRuntimeDerivedFields(summary)
}

// ObserveVisionNativeProvisionalSemantic records a bridge-owned provisional seam
// semantic directly. Producers may also clear the current provisional semantic
// by publishing VisionNativeProvisionalSemanticNone when later transport/protocol
// facts supersede the provisional state.
func ObserveVisionNativeProvisionalSemantic(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, semantic VisionNativeProvisionalSemantic) {
	observeVisionNativeProvisionalSemanticWithSource(conn, kind, origin, semantic, VisionNativeProvisionalSemanticSourceBridgeProducer)
}

// ObserveVisionNativeExplicitProvisionalSemantic records a provisional semantic
// from a true explicit/native producer. This is reserved for future transport-
// originated semantic publication and intentionally distinct from bridge-owned
// publication.
func ObserveVisionNativeExplicitProvisionalSemantic(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, semantic VisionNativeProvisionalSemantic) {
	observeVisionNativeProvisionalSemanticWithSource(conn, kind, origin, semantic, VisionNativeProvisionalSemanticSourceExplicitProducer)
}

func observeVisionNativeProvisionalSemanticWithSource(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, semantic VisionNativeProvisionalSemantic, source VisionNativeProvisionalSemanticSource) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	if semantic == "" {
		semantic = VisionNativeProvisionalSemanticNone
	}
	if semantic == VisionNativeProvisionalSemanticNone {
		summary.NativeProvisionalSemantic = VisionNativeProvisionalSemanticNone
		summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceNone
		refreshVisionRuntimeDerivedFields(summary)
		return
	}
	summary.NativeProvisionalSemantic = semantic
	summary.NativeProvisionalSource = source
	refreshVisionRuntimeDerivedFields(summary)
}

// ObserveVisionNativeProvisionalOutcome records a bridge-owned provisional seam
// outcome directly. Producers may also clear the current provisional outcome by
// publishing VisionNativeProvisionalOutcomeNone when later facts supersede it.
func ObserveVisionNativeProvisionalOutcome(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, outcome VisionNativeProvisionalOutcome) {
	observeVisionNativeProvisionalOutcomeWithSource(conn, kind, origin, outcome, VisionNativeProvisionalOutcomeSourceBridgeProducer)
}

// ObserveVisionNativeExplicitProvisionalOutcome records a provisional outcome
// from a true explicit/native producer. This is intentionally distinct from
// bridge-owned publication so the seam can trust transport-originated
// terminal outcomes without conflating them with bridge synthesis.
func ObserveVisionNativeExplicitProvisionalOutcome(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, outcome VisionNativeProvisionalOutcome) {
	observeVisionNativeProvisionalOutcomeWithSource(conn, kind, origin, outcome, VisionNativeProvisionalOutcomeSourceExplicitProducer)
}

func observeVisionNativeProvisionalOutcomeWithSource(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, outcome VisionNativeProvisionalOutcome, source VisionNativeProvisionalOutcomeSource) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	if outcome == "" {
		outcome = VisionNativeProvisionalOutcomeNone
	}
	if outcome == VisionNativeProvisionalOutcomeNone {
		summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeNone
		summary.NativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceNone
		summary.NativeProvisionalTerminalReason = VisionNativeProvisionalTerminalReasonNone
		refreshVisionRuntimeDerivedFields(summary)
		return
	}
	summary.NativeProvisionalOutcome = outcome
	summary.NativeProvisionalOutcomeSource = source
	if outcome != VisionNativeProvisionalOutcomeBenignClose && outcome != VisionNativeProvisionalOutcomeFailedPending {
		summary.NativeProvisionalTerminalReason = VisionNativeProvisionalTerminalReasonNone
	}
	refreshVisionRuntimeDerivedFields(summary)
}

// ObserveVisionNativeProvisionalTerminalReason records a terminal reason for a
// producer-owned provisional lifecycle. It is meaningful only for terminal
// outcomes like benign close or failed pending.
func ObserveVisionNativeProvisionalTerminalReason(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, reason VisionNativeProvisionalTerminalReason) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	if reason == "" {
		reason = VisionNativeProvisionalTerminalReasonNone
	}
	summary.NativeProvisionalTerminalReason = reason
	refreshVisionRuntimeDerivedFields(summary)
}

// ResolveVisionNativeProvisionalNoDetachAtSemanticBoundary promotes the native
// provisional lifecycle into an explicit no-detach resolution at the Vision
// command boundary. This is only valid for native deferred ingress after a
// provisional command0-bidirectional state has actually been observed.
func ResolveVisionNativeProvisionalNoDetachAtSemanticBoundary(source *VisionTransitionSource) {
	if source == nil || source.Conn() == nil {
		return
	}
	snap := source.Snapshot()
	if snap.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		return
	}
	if snap.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional &&
		snap.NativeProvisionalSemantic != VisionNativeProvisionalSemanticCommand0Bidirectional &&
		!shouldResolveVisionNativeNoDetachFromTransport(snap) {
		return
	}
	// Explicit command=1 at the Vision boundary must supersede an earlier
	// transport-published provisional terminal outcome. This is protocol truth,
	// not a bridge-side fallback, so publish it through the explicit producer
	// path rather than the bridge-producer path.
	ObserveVisionNativeExplicitProvisionalOutcome(source.Conn(), source.Kind(), snap.IngressOrigin, VisionNativeProvisionalOutcomeResolvedNoDetach)
	ObserveVisionNativeProvisionalTerminalReason(source.Conn(), source.Kind(), snap.IngressOrigin, VisionNativeProvisionalTerminalReasonNone)
	ObserveVisionNativeExplicitProvisionalSemantic(source.Conn(), source.Kind(), snap.IngressOrigin, VisionNativeProvisionalSemanticNone)
}

func shouldResolveVisionNativeNoDetachFromTransport(snap VisionTransitionSnapshot) bool {
	if snap.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		return false
	}
	if snap.TransportProgress != VisionTransportProgressBidirectional {
		return false
	}
	if snap.TransportDetachStatus != VisionTransportDetachStatusNone {
		return false
	}
	if snap.DrainCount != 0 || snap.TransportDrainCount != 0 {
		return false
	}
	return true
}

// ObserveVisionTransitionDrain records buffered/drained data returned at the
// seam without requiring debug logging or a VisionTransitionSource wrapper.
//
// This is the producer-grade API future native detach/bridge code should use
// when it materializes consumed plaintext or raw-ahead bytes.
func ObserveVisionTransitionDrain(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, mode VisionDrainMode, plaintextLen int, rawAheadLen int) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	if mode != "" {
		summary.DrainMode = mergeVisionDrainMode(summary.DrainMode, mode)
	}
	summary.DrainCount++
	summary.DrainPlaintextBytes += plaintextLen
	summary.DrainRawAheadBytes += rawAheadLen
	refreshVisionRuntimeDerivedFields(summary)
}

// ObserveVisionTransportDrain records transport-layer deferred detach/drain
// observations. This is intentionally separate from ObserveVisionTransitionDrain:
// transport observation does not imply the higher-level seam accepted the detach
// boundary, only that the native/deferred transport completed a drain event.
func ObserveVisionTransportDrain(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, mode VisionDrainMode, plaintextLen int, rawAheadLen int) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	if mode != "" {
		summary.TransportDrainMode = mergeVisionDrainMode(summary.TransportDrainMode, mode)
	}
	summary.TransportDrainCount++
	summary.TransportDrainPlaintextLen += plaintextLen
	summary.TransportDrainRawAheadLen += rawAheadLen
	refreshVisionRuntimeDerivedFields(summary)
}

func ObserveVisionTransportLifecycle(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, event tls.DeferredRustLifecycleEvent) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	switch event {
	case tls.DeferredRustLifecycleDeferredActive:
		summary.TransportLifecycleState = mergeVisionTransportLifecycleState(summary.TransportLifecycleState, VisionTransportLifecycleDeferredActive)
	case tls.DeferredRustLifecycleDetachCompleted:
		summary.TransportLifecycleState = mergeVisionTransportLifecycleState(summary.TransportLifecycleState, VisionTransportLifecycleDeferredDetach)
		summary.TransportDetachStatus = mergeVisionTransportDetachStatus(summary.TransportDetachStatus, VisionTransportDetachStatusCompleted)
	case tls.DeferredRustLifecycleDetachFailed:
		summary.TransportDetachStatus = mergeVisionTransportDetachStatus(summary.TransportDetachStatus, VisionTransportDetachStatusFailed)
	case tls.DeferredRustLifecycleKTLSEnabled:
		summary.TransportLifecycleState = mergeVisionTransportLifecycleState(summary.TransportLifecycleState, VisionTransportLifecycleKTLSEnabled)
		summary.TransportKTLSPromotion = mergeVisionTransportKTLSPromotion(summary.TransportKTLSPromotion, VisionTransportKTLSPromotionEnabled)
	case tls.DeferredRustLifecycleKTLSCooldown:
		summary.TransportKTLSPromotion = mergeVisionTransportKTLSPromotion(summary.TransportKTLSPromotion, VisionTransportKTLSPromotionCooldown)
	case tls.DeferredRustLifecycleKTLSUnsupported:
		summary.TransportKTLSPromotion = mergeVisionTransportKTLSPromotion(summary.TransportKTLSPromotion, VisionTransportKTLSPromotionUnsupported)
	case tls.DeferredRustLifecycleKTLSFailed:
		summary.TransportKTLSPromotion = mergeVisionTransportKTLSPromotion(summary.TransportKTLSPromotion, VisionTransportKTLSPromotionFailed)
	}
	refreshVisionRuntimeDerivedFields(summary)
}

func ObserveVisionTransportProgress(conn gonet.Conn, kind VisionTransitionKind, origin VisionIngressOrigin, event tls.DeferredRustProgressEvent) {
	summary := ensureVisionTransitionSummary(conn)
	if summary == nil {
		return
	}
	if kind != "" && (summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque) {
		summary.Kind = kind
	}
	if origin != "" && origin != VisionIngressOriginUnknown &&
		(summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown) {
		summary.IngressOrigin = origin
	}
	switch event.Direction {
	case tls.DeferredRustProgressRead:
		summary.TransportReadOps++
		summary.TransportReadBytes += event.Bytes
	case tls.DeferredRustProgressWrite:
		summary.TransportWriteOps++
		summary.TransportWriteBytes += event.Bytes
	}
	refreshVisionRuntimeDerivedFields(summary)
}

func observeVisionTransportDeferredDrain(conn gonet.Conn, plaintextLen int, rawAheadLen int) {
	kind := VisionTransitionKindDeferredRust
	origin := VisionIngressOriginUnknown
	if summary, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		if summary.Kind != "" {
			kind = summary.Kind
		}
		if summary.IngressOrigin != "" {
			origin = summary.IngressOrigin
		}
	}
	ObserveVisionTransportDrain(conn, kind, origin, VisionDrainModeDeferred, plaintextLen, rawAheadLen)
}

func observeVisionTransportLifecycleEvent(conn gonet.Conn, event tls.DeferredRustLifecycleEvent) {
	kind := VisionTransitionKindDeferredRust
	origin := VisionIngressOriginUnknown
	if summary, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		if summary.Kind != "" {
			kind = summary.Kind
		}
		if summary.IngressOrigin != "" {
			origin = summary.IngressOrigin
		}
	}
	ObserveVisionTransportLifecycle(conn, kind, origin, event)
}

func observeVisionTransportProgressEvent(conn gonet.Conn, event tls.DeferredRustProgressEvent) {
	kind := VisionTransitionKindDeferredRust
	origin := VisionIngressOriginUnknown
	if summary, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		if summary.Kind != "" {
			kind = summary.Kind
		}
		if summary.IngressOrigin != "" {
			origin = summary.IngressOrigin
		}
	}
	ObserveVisionTransportProgress(conn, kind, origin, event)
}

func observeVisionTransportProvisionalEvent(conn gonet.Conn, obs tls.DeferredRustProvisionalObservation) {
	kind := VisionTransitionKindDeferredRust
	origin := VisionIngressOriginUnknown
	if summary, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		if summary.Kind != "" {
			kind = summary.Kind
		}
		if summary.IngressOrigin != "" {
			origin = summary.IngressOrigin
		}
	}
	switch obs.Semantic {
	case tls.DeferredRustProvisionalSemanticCommand0Bidirectional:
		observeVisionNativeProvisionalSemanticWithSource(conn, kind, origin, VisionNativeProvisionalSemanticCommand0Bidirectional, VisionNativeProvisionalSemanticSourceTransportProducer)
	default:
		observeVisionNativeProvisionalSemanticWithSource(conn, kind, origin, VisionNativeProvisionalSemanticNone, VisionNativeProvisionalSemanticSourceTransportProducer)
	}
	switch obs.Outcome {
	case tls.DeferredRustProvisionalOutcomeActive:
		observeVisionNativeProvisionalOutcomeWithSource(conn, kind, origin, VisionNativeProvisionalOutcomeActive, VisionNativeProvisionalOutcomeSourceTransportProducer)
	case tls.DeferredRustProvisionalOutcomeResolvedDirect:
		ObserveVisionNativeExplicitProvisionalOutcome(conn, kind, origin, VisionNativeProvisionalOutcomeResolvedDirect)
	case tls.DeferredRustProvisionalOutcomeBenignClose:
		ObserveVisionNativeExplicitProvisionalOutcome(conn, kind, origin, VisionNativeProvisionalOutcomeBenignClose)
	case tls.DeferredRustProvisionalOutcomeFailedPending:
		ObserveVisionNativeExplicitProvisionalOutcome(conn, kind, origin, VisionNativeProvisionalOutcomeFailedPending)
	case tls.DeferredRustProvisionalOutcomeTerminatedPending:
		ObserveVisionNativeExplicitProvisionalOutcome(conn, kind, origin, VisionNativeProvisionalOutcomeTerminatedPending)
	default:
		ObserveVisionNativeExplicitProvisionalOutcome(conn, kind, origin, VisionNativeProvisionalOutcomeNone)
	}
	switch obs.TerminalReason {
	case tls.DeferredRustProvisionalTerminalReasonLocalClose:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonLocalClose)
	case tls.DeferredRustProvisionalTerminalReasonEOF:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonEOF)
	case tls.DeferredRustProvisionalTerminalReasonClosed:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonClosed)
	case tls.DeferredRustProvisionalTerminalReasonReset:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonReset)
	case tls.DeferredRustProvisionalTerminalReasonBrokenPipe:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonBrokenPipe)
	case tls.DeferredRustProvisionalTerminalReasonBadMessage:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonBadMessage)
	case tls.DeferredRustProvisionalTerminalReasonEIO:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonEIO)
	case tls.DeferredRustProvisionalTerminalReasonOther:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonOther)
	default:
		ObserveVisionNativeProvisionalTerminalReason(conn, kind, origin, VisionNativeProvisionalTerminalReasonNone)
	}
	switch obs.Outcome {
	case tls.DeferredRustProvisionalOutcomeBenignClose:
		wakeVisionResponseLoop(context.Background(), conn, "transport-provisional-benign-close")
	case tls.DeferredRustProvisionalOutcomeFailedPending, tls.DeferredRustProvisionalOutcomeTerminatedPending:
		wakeVisionResponseLoop(context.Background(), conn, "transport-provisional-failed-pending")
	}
}

// BuildVisionTransitionSource preserves the existing Vision buffer extraction
// behavior while making the seam explicit. Callers remain responsible for any
// policy/version checks that are specific to their direction.
func BuildVisionTransitionSource(publicConn gonet.Conn, innerConn gonet.Conn) (*VisionTransitionSource, error) {
	if publicConn == nil {
		publicConn = innerConn
	}
	origin := snapshotVisionIngressOrigin(publicConn, innerConn)
	if source, handled, err := buildVisionTransitionSourceForConn(publicConn, publicConn); handled {
		if source != nil {
			source.origin = origin
		}
		return source, err
	}
	if innerConn != nil && innerConn != publicConn {
		if source, handled, err := buildVisionTransitionSourceForConn(publicConn, innerConn); handled {
			if source != nil {
				source.origin = origin
			}
			return source, err
		}
	}
	return nil, errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
}

func snapshotVisionIngressOrigin(publicConn gonet.Conn, innerConn gonet.Conn) VisionIngressOrigin {
	if summary, ok := SnapshotVisionTransitionSummary(publicConn, innerConn); ok {
		return summary.IngressOrigin
	}
	return VisionIngressOriginUnknown
}

func ensureVisionTransitionSummary(conn gonet.Conn) *VisionTransitionSummary {
	key, ok := visionTransitionTraceKey(conn, 0)
	if !ok {
		return nil
	}
	value, _ := visionTransitionTraceByConn.LoadOrStore(key, newVisionTransitionSummary())
	summary, _ := value.(*VisionTransitionSummary)
	return summary
}

func SnapshotVisionTransitionSummary(primaryConn gonet.Conn, secondaryConn gonet.Conn) (VisionTransitionSummary, bool) {
	var merged VisionTransitionSummary
	found := false
	if summary, ok := snapshotVisionTransitionSummaryForConn(primaryConn, 0); ok {
		merged = mergeVisionTransitionSummaries(merged, summary)
		found = true
	}
	if secondaryConn != nil && secondaryConn != primaryConn {
		if summary, ok := snapshotVisionTransitionSummaryForConn(secondaryConn, 0); ok {
			merged = mergeVisionTransitionSummaries(merged, summary)
			found = true
		}
	}
	if found {
		refreshVisionRuntimeDerivedFields(&merged)
	}
	return merged, found
}

func SnapshotVisionBridgeAssessmentStats() VisionBridgeAssessmentStats {
	now := visionBridgeAssessmentNowFn()
	var total VisionBridgeAssessmentStats
	visionBridgeAssessmentStatsByScope.Range(func(_, value any) bool {
		window, _ := value.(*visionBridgeAssessmentWindow)
		if window == nil {
			return true
		}
		total = addVisionBridgeAssessmentStats(total, window.snapshot(now))
		return true
	})
	return total
}

func SnapshotVisionBridgeAssessmentStatsForScope(scope string) VisionBridgeAssessmentStats {
	window := loadVisionBridgeAssessmentWindow(normalizeVisionBridgeAssessmentScope(scope))
	if window == nil {
		return VisionBridgeAssessmentStats{}
	}
	return window.snapshot(visionBridgeAssessmentNowFn())
}

func EnsureVisionBridgeProbeEpoch(scope string, budget uint64, duration time.Duration) VisionBridgeProbeSnapshot {
	scope = normalizeVisionBridgeAssessmentScope(scope)
	now := visionBridgeProbeNowFn()
	epoch := ensureVisionBridgeProbeEpoch(scope)
	if epoch == nil {
		return VisionBridgeProbeSnapshot{ScopeKey: scope, State: VisionBridgeProbeStateInactive, Verdict: VisionBridgeProbeVerdictNone}
	}
	return epoch.ensure(now, budget, duration)
}

func SnapshotVisionBridgeProbeEpochForScope(scope string) VisionBridgeProbeSnapshot {
	scope = normalizeVisionBridgeAssessmentScope(scope)
	epoch := loadVisionBridgeProbeEpoch(scope)
	if epoch == nil {
		return VisionBridgeProbeSnapshot{ScopeKey: scope, State: VisionBridgeProbeStateInactive, Verdict: VisionBridgeProbeVerdictNone}
	}
	return epoch.snapshot(visionBridgeProbeNowFn())
}

func consumeVisionTransitionSummary(primaryConn gonet.Conn, secondaryConn gonet.Conn) (VisionTransitionSummary, bool) {
	var merged VisionTransitionSummary
	found := false
	if summary, ok := consumeVisionTransitionSummaryForConn(primaryConn, 0); ok {
		merged = mergeVisionTransitionSummaries(merged, summary)
		found = true
	}
	if secondaryConn != nil && secondaryConn != primaryConn {
		if summary, ok := consumeVisionTransitionSummaryForConn(secondaryConn, 0); ok {
			merged = mergeVisionTransitionSummaries(merged, summary)
			found = true
		}
	}
	if found {
		refreshVisionRuntimeDerivedFields(&merged)
	}
	return merged, found
}

func refreshVisionRuntimeDerivedFields(summary *VisionTransitionSummary) {
	refreshVisionDerivedFields(summary, VisionPendingQualityNone, false, nil)
}

func finalizeVisionTransitionSummary(summary *VisionTransitionSummary, snap *pipeline.DecisionSnapshot) {
	refreshVisionDerivedFields(summary, deriveVisionPendingQuality(*summary, snap), true, snap)
}

func refreshVisionDerivedFields(summary *VisionTransitionSummary, pendingQuality VisionPendingQuality, final bool, snap *pipeline.DecisionSnapshot) {
	if summary == nil {
		return
	}
	summary.PendingQuality = pendingQuality
	summary.DrainRelation = deriveVisionDrainRelation(*summary)
	summary.TransportProgress = deriveVisionTransportProgress(*summary)
	summary.BridgeAssessment = deriveVisionBridgeAssessment(*summary)
	summary.PendingClass = deriveVisionPendingClass(*summary)
	summary.PendingGap = deriveVisionPendingGap(*summary)
	derivedSemantic := deriveVisionNativeProvisionalSemantic(*summary)
	if shouldDeriveLiveVisionNativeProvisionalSemantic(summary, final) {
		summary.NativeProvisionalSemantic = derivedSemantic
		if derivedSemantic == VisionNativeProvisionalSemanticNone {
			summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceNone
		} else {
			summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceDerived
		}
	} else if !isVisionNativeProvisionalProducerSource(summary.NativeProvisionalSource) {
		summary.NativeProvisionalSemantic = VisionNativeProvisionalSemanticNone
		summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceNone
	}
	reconcileVisionNativeProvisionalSemantic(summary, derivedSemantic)
	latchVisionNativeProvisionalObservation(summary)
	reconcileVisionNativeProvisionalOutcome(summary, final)
	if shouldDeriveVisionNativeProvisionalOutcome(summary, final) {
		summary.NativeProvisionalOutcome = deriveVisionNativeProvisionalOutcome(*summary)
		if summary.NativeProvisionalOutcome == VisionNativeProvisionalOutcomeNone {
			summary.NativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceNone
		} else {
			summary.NativeProvisionalOutcomeSource = visionDerivedNativeProvisionalOutcomeSource(*summary, final)
		}
	}
	applyVisionExplicitSemanticSupersession(summary)
	applyVisionFinalProvisionalOutcomeFallback(summary, snap, final)
	reconcileVisionNativeProvisionalTerminalReason(summary)
	applyVisionProvisionalOutcomeToPending(summary)
	normalizeVisionTransportOwnedTerminalOutcome(summary, snap, final)
	normalizeVisionBridgeOwnedTerminalOutcome(summary, snap, final)
	enforceVisionBridgeOwnedLocalTerminalReason(summary, snap, final)
}

func applyVisionFinalProvisionalOutcomeFallback(summary *VisionTransitionSummary, snap *pipeline.DecisionSnapshot, final bool) {
	if summary == nil || !final {
		return
	}
	// Preserve explicit/direct protocol truth and any already-published terminal
	// provisional outcome. This fallback closes the gap where a producer-owned
	// provisional lifecycle was observed, but terminal publication never
	// arrived before final summary. The live active field may already have been
	// cleared while the observed producer-owned semantic remains latched, so we
	// key this fallback off the observed lifecycle rather than the current live
	// outcome alone.
	if summary.NativeProvisionalOutcome == VisionNativeProvisionalOutcomeResolvedDirect ||
		summary.NativeProvisionalOutcome == VisionNativeProvisionalOutcomeResolvedNoDetach {
		return
	}
	hasObservedProducer := summary.NativeProvisionalObserved == VisionNativeProvisionalSemanticCommand0Bidirectional &&
		isVisionNativeProvisionalProducerSource(summary.NativeProvisionalObservedSource)
	hasActiveProducer := summary.NativeProvisionalOutcome == VisionNativeProvisionalOutcomeActive &&
		isVisionNativeProvisionalOutcomeProducerSource(summary.NativeProvisionalOutcomeSource)
	if !hasObservedProducer && !hasActiveProducer {
		return
	}
	switch summary.PendingQuality {
	case VisionPendingQualityFailure:
		terminalReason := deriveVisionPendingTerminalReasonFromDecision(snap, VisionPendingQualityFailure)
		summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeFailedPending
		summary.NativeProvisionalOutcomeSource = visionPendingTerminalOutcomeSource(terminalReason)
		summary.NativeProvisionalTerminalReason = terminalReason
	case VisionPendingQualityBenign:
		terminalReason := deriveVisionPendingTerminalReasonFromDecision(snap, VisionPendingQualityBenign)
		summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeBenignClose
		summary.NativeProvisionalOutcomeSource = visionPendingTerminalOutcomeSource(terminalReason)
		summary.NativeProvisionalTerminalReason = terminalReason
	}
}

func deriveVisionPendingTerminalReasonFromDecision(snap *pipeline.DecisionSnapshot, pendingQuality VisionPendingQuality) VisionNativeProvisionalTerminalReason {
	if snap == nil {
		if pendingQuality == VisionPendingQualityBenign {
			return VisionNativeProvisionalTerminalReasonLocalClose
		}
		return VisionNativeProvisionalTerminalReasonOther
	}
	switch snap.UserspaceExit {
	case pipeline.UserspaceExitTimeout,
		pipeline.UserspaceExitLocalCloseNoResponse,
		pipeline.UserspaceExitStableUserspaceClose,
		pipeline.UserspaceExitComplete:
		return VisionNativeProvisionalTerminalReasonLocalClose
	case pipeline.UserspaceExitRemoteEOFNoResponse:
		return VisionNativeProvisionalTerminalReasonEOF
	case pipeline.UserspaceExitRemoteReset:
		return VisionNativeProvisionalTerminalReasonReset
	default:
		if pendingQuality == VisionPendingQualityBenign {
			return VisionNativeProvisionalTerminalReasonLocalClose
		}
		return VisionNativeProvisionalTerminalReasonOther
	}
}

func visionPendingTerminalOutcomeSource(reason VisionNativeProvisionalTerminalReason) VisionNativeProvisionalOutcomeSource {
	if reason == VisionNativeProvisionalTerminalReasonLocalClose {
		return VisionNativeProvisionalOutcomeSourceBridgeProducer
	}
	return VisionNativeProvisionalOutcomeSourceExplicitProducer
}

func applyVisionExplicitSemanticSupersession(summary *VisionTransitionSummary) {
	if summary == nil {
		return
	}
	switch {
	case summary.Uplink.Semantic == VisionSemanticExplicitDirect ||
		summary.Downlink.Semantic == VisionSemanticExplicitDirect:
		summary.NativeProvisionalSemantic = VisionNativeProvisionalSemanticNone
		summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceNone
		summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeResolvedDirect
		summary.NativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceExplicitProducer
		summary.NativeProvisionalTerminalReason = VisionNativeProvisionalTerminalReasonNone
	case summary.Uplink.Semantic == VisionSemanticExplicitNoDetach ||
		summary.Downlink.Semantic == VisionSemanticExplicitNoDetach:
		summary.NativeProvisionalSemantic = VisionNativeProvisionalSemanticNone
		summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceNone
		summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeResolvedNoDetach
		summary.NativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceExplicitProducer
		summary.NativeProvisionalTerminalReason = VisionNativeProvisionalTerminalReasonNone
	}
}

func shouldDeriveLiveVisionNativeProvisionalSemantic(summary *VisionTransitionSummary, final bool) bool {
	if summary == nil {
		return false
	}
	if isVisionNativeProvisionalProducerSource(summary.NativeProvisionalSource) {
		return false
	}
	if summary.IngressOrigin == VisionIngressOriginNativeRealityDeferred &&
		isVisionNativeProvisionalTransportSource(summary.NativeProvisionalObservedSource) {
		return false
	}
	if !final && summary.IngressOrigin == VisionIngressOriginNativeRealityDeferred {
		return false
	}
	return true
}

func shouldDeriveVisionNativeProvisionalOutcome(summary *VisionTransitionSummary, final bool) bool {
	if summary == nil {
		return false
	}
	if isVisionNativeProvisionalOutcomeProducerSource(summary.NativeProvisionalOutcomeSource) {
		return false
	}
	if summary.IngressOrigin == VisionIngressOriginNativeRealityDeferred &&
		isVisionNativeProvisionalTransportSource(summary.NativeProvisionalObservedSource) {
		return false
	}
	if !final && summary.IngressOrigin == VisionIngressOriginNativeRealityDeferred {
		return false
	}
	return true
}

func visionDerivedNativeProvisionalOutcomeSource(summary VisionTransitionSummary, final bool) VisionNativeProvisionalOutcomeSource {
	return VisionNativeProvisionalOutcomeSourceDerived
}

func reconcileVisionNativeProvisionalSemantic(summary *VisionTransitionSummary, desired VisionNativeProvisionalSemantic) {
	if summary == nil {
		return
	}
	if summary.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		if summary.NativeProvisionalSource == VisionNativeProvisionalSemanticSourceTransportProducer {
			summary.NativeProvisionalSemantic = VisionNativeProvisionalSemanticNone
			summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceNone
		}
		return
	}
	if isVisionNativeProvisionalTransportSource(summary.NativeProvisionalObservedSource) &&
		!isVisionNativeProvisionalProducerSource(summary.NativeProvisionalSource) {
		summary.NativeProvisionalSemantic = VisionNativeProvisionalSemanticNone
		summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceNone
		return
	}
	if summary.NativeProvisionalSource == VisionNativeProvisionalSemanticSourceTransportProducer &&
		desired == VisionNativeProvisionalSemanticNone {
		summary.NativeProvisionalSemantic = VisionNativeProvisionalSemanticNone
		summary.NativeProvisionalSource = VisionNativeProvisionalSemanticSourceNone
	}
}

func reconcileVisionNativeProvisionalOutcome(summary *VisionTransitionSummary, final bool) {
	if summary == nil {
		return
	}
	if isVisionNativeProvisionalOutcomeProducerSource(summary.NativeProvisionalOutcomeSource) {
		return
	}
	if summary.IngressOrigin == VisionIngressOriginNativeRealityDeferred &&
		isVisionNativeProvisionalTransportSource(summary.NativeProvisionalObservedSource) {
		if summary.NativeProvisionalOutcomeSource == VisionNativeProvisionalOutcomeSourceDerived {
			summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeNone
			summary.NativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceNone
		}
		return
	}
	if !isVisionNativeProvisionalProducerSource(summary.NativeProvisionalObservedSource) {
		if summary.NativeProvisionalOutcomeSource == VisionNativeProvisionalOutcomeSourceDerived {
			summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeNone
			summary.NativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceNone
		}
		return
	}
	desired := deriveVisionNativeProvisionalOutcome(*summary)
	if desired == VisionNativeProvisionalOutcomeNone {
		if summary.NativeProvisionalOutcomeSource == VisionNativeProvisionalOutcomeSourceDerived {
			summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeNone
			summary.NativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceNone
		}
		return
	}
	summary.NativeProvisionalOutcome = desired
	summary.NativeProvisionalOutcomeSource = visionDerivedNativeProvisionalOutcomeSource(*summary, final)
}

func reconcileVisionNativeProvisionalTerminalReason(summary *VisionTransitionSummary) {
	if summary == nil {
		return
	}
	switch summary.NativeProvisionalOutcome {
	case VisionNativeProvisionalOutcomeNone,
		VisionNativeProvisionalOutcomeActive,
		VisionNativeProvisionalOutcomeResolvedDirect,
		VisionNativeProvisionalOutcomeResolvedNoDetach:
		summary.NativeProvisionalTerminalReason = VisionNativeProvisionalTerminalReasonNone
	case VisionNativeProvisionalOutcomeBenignClose:
		if summary.NativeProvisionalTerminalReason == VisionNativeProvisionalTerminalReasonNone {
			summary.NativeProvisionalTerminalReason = VisionNativeProvisionalTerminalReasonLocalClose
		}
	case VisionNativeProvisionalOutcomeFailedPending, VisionNativeProvisionalOutcomeTerminatedPending:
		if summary.NativeProvisionalTerminalReason == VisionNativeProvisionalTerminalReasonNone {
			summary.NativeProvisionalTerminalReason = VisionNativeProvisionalTerminalReasonOther
		}
	}
}

func deriveVisionNativeBridgeProducerOutcome(summary VisionTransitionSummary, desiredSemantic VisionNativeProvisionalSemantic) VisionNativeProvisionalOutcome {
	if summary.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		return VisionNativeProvisionalOutcomeNone
	}
	if summary.Uplink.Semantic == VisionSemanticExplicitDirect ||
		summary.Downlink.Semantic == VisionSemanticExplicitDirect ||
		summary.DrainCount > 0 ||
		summary.DrainMode != VisionDrainModeNone {
		return VisionNativeProvisionalOutcomeResolvedDirect
	}
	if summary.Uplink.Semantic == VisionSemanticExplicitNoDetach ||
		summary.Downlink.Semantic == VisionSemanticExplicitNoDetach {
		return VisionNativeProvisionalOutcomeResolvedNoDetach
	}
	if desiredSemantic != VisionNativeProvisionalSemanticNone {
		return VisionNativeProvisionalOutcomeActive
	}
	return VisionNativeProvisionalOutcomeNone
}

func snapshotVisionTransitionSummaryForConn(conn gonet.Conn, depth int) (VisionTransitionSummary, bool) {
	if key, ok := visionTransitionTraceKey(conn, depth); ok {
		if value, ok := visionTransitionTraceByConn.Load(key); ok {
			if summary, ok := value.(*VisionTransitionSummary); ok && summary != nil {
				return *summary, true
			}
		}
	}
	return VisionTransitionSummary{}, false
}

func consumeVisionTransitionSummaryForConn(conn gonet.Conn, depth int) (VisionTransitionSummary, bool) {
	if key, ok := visionTransitionTraceKey(conn, depth); ok {
		if value, ok := visionTransitionTraceByConn.LoadAndDelete(key); ok {
			if summary, ok := value.(*VisionTransitionSummary); ok && summary != nil {
				return *summary, true
			}
		}
	}
	return VisionTransitionSummary{}, false
}

func mergeVisionTransitionSummaries(dst VisionTransitionSummary, src VisionTransitionSummary) VisionTransitionSummary {
	if dst.Kind == "" || dst.Kind == VisionTransitionKindOpaque {
		dst.Kind = src.Kind
	}
	if dst.IngressOrigin == "" || dst.IngressOrigin == VisionIngressOriginUnknown {
		dst.IngressOrigin = src.IngressOrigin
	}
	if dst.ScopeKey == "" || dst.ScopeKey == visionBridgeAssessmentUnscopedKey {
		dst.ScopeKey = src.ScopeKey
	}
	dst.Uplink.Command0Count += src.Uplink.Command0Count
	dst.Uplink.Command1Count += src.Uplink.Command1Count
	dst.Uplink.Command2Count += src.Uplink.Command2Count
	dst.Uplink.PayloadBypass = dst.Uplink.PayloadBypass || src.Uplink.PayloadBypass
	dst.Uplink.Semantic = mergeVisionSemantic(dst.Uplink.Semantic, src.Uplink.Semantic)
	dst.Downlink.Command0Count += src.Downlink.Command0Count
	dst.Downlink.Command1Count += src.Downlink.Command1Count
	dst.Downlink.Command2Count += src.Downlink.Command2Count
	dst.Downlink.PayloadBypass = dst.Downlink.PayloadBypass || src.Downlink.PayloadBypass
	dst.Downlink.Semantic = mergeVisionSemantic(dst.Downlink.Semantic, src.Downlink.Semantic)
	dst.NativeProvisionalSemantic = mergeVisionNativeProvisionalSemantic(dst.NativeProvisionalSemantic, src.NativeProvisionalSemantic)
	dst.NativeProvisionalSource = mergeVisionNativeProvisionalSemanticSource(dst.NativeProvisionalSource, src.NativeProvisionalSource)
	dst.NativeProvisionalObserved = mergeVisionNativeProvisionalSemantic(dst.NativeProvisionalObserved, src.NativeProvisionalObserved)
	dst.NativeProvisionalObservedSource = mergeVisionNativeProvisionalSemanticSource(dst.NativeProvisionalObservedSource, src.NativeProvisionalObservedSource)
	dst.NativeProvisionalOutcome = mergeVisionNativeProvisionalOutcome(dst.NativeProvisionalOutcome, src.NativeProvisionalOutcome)
	dst.NativeProvisionalOutcomeSource = mergeVisionNativeProvisionalOutcomeSource(dst.NativeProvisionalOutcomeSource, src.NativeProvisionalOutcomeSource)
	dst.NativeProvisionalTerminalReason = mergeVisionNativeProvisionalTerminalReason(dst.NativeProvisionalTerminalReason, src.NativeProvisionalTerminalReason)
	dst.DrainMode = mergeVisionDrainMode(dst.DrainMode, src.DrainMode)
	dst.DrainCount += src.DrainCount
	dst.DrainPlaintextBytes += src.DrainPlaintextBytes
	dst.DrainRawAheadBytes += src.DrainRawAheadBytes
	dst.TransportDrainMode = mergeVisionDrainMode(dst.TransportDrainMode, src.TransportDrainMode)
	dst.TransportDrainCount += src.TransportDrainCount
	dst.TransportDrainPlaintextLen += src.TransportDrainPlaintextLen
	dst.TransportDrainRawAheadLen += src.TransportDrainRawAheadLen
	dst.DrainRelation = mergeVisionDrainRelation(dst.DrainRelation, src.DrainRelation)
	dst.BridgeAssessment = mergeVisionBridgeAssessment(dst.BridgeAssessment, src.BridgeAssessment)
	dst.PendingQuality = mergeVisionPendingQuality(dst.PendingQuality, src.PendingQuality)
	dst.PendingClass = mergeVisionPendingClass(dst.PendingClass, src.PendingClass)
	dst.PendingGap = mergeVisionPendingGap(dst.PendingGap, src.PendingGap)
	dst.TransportReadOps += src.TransportReadOps
	dst.TransportReadBytes += src.TransportReadBytes
	dst.TransportWriteOps += src.TransportWriteOps
	dst.TransportWriteBytes += src.TransportWriteBytes
	dst.TransportProgress = mergeVisionTransportProgress(dst.TransportProgress, src.TransportProgress)
	dst.TransportLifecycleState = mergeVisionTransportLifecycleState(dst.TransportLifecycleState, src.TransportLifecycleState)
	dst.TransportDetachStatus = mergeVisionTransportDetachStatus(dst.TransportDetachStatus, src.TransportDetachStatus)
	dst.TransportKTLSPromotion = mergeVisionTransportKTLSPromotion(dst.TransportKTLSPromotion, src.TransportKTLSPromotion)
	return dst
}

func mergeVisionSemantic(dst VisionSemantic, src VisionSemantic) VisionSemantic {
	if visionSemanticRank(src) > visionSemanticRank(dst) {
		return src
	}
	if dst == "" {
		return VisionSemanticUnknown
	}
	return dst
}

func visionSemanticRank(semantic VisionSemantic) int {
	switch semantic {
	case VisionSemanticExplicitDirect:
		return 3
	case VisionSemanticExplicitNoDetach:
		return 2
	case VisionSemanticPayloadBypass:
		return 1
	default:
		return 0
	}
}

func mergeVisionDrainMode(dst VisionDrainMode, src VisionDrainMode) VisionDrainMode {
	switch {
	case src == "" || src == VisionDrainModeNone:
		if dst == "" {
			return VisionDrainModeNone
		}
		return dst
	case dst == "" || dst == VisionDrainModeNone:
		return src
	case dst == src:
		return dst
	default:
		return VisionDrainModeMixed
	}
}

func mergeVisionTransportLifecycleState(dst VisionTransportLifecycleState, src VisionTransportLifecycleState) VisionTransportLifecycleState {
	if visionTransportLifecycleRank(src) > visionTransportLifecycleRank(dst) {
		return src
	}
	if dst == "" {
		return VisionTransportLifecycleUnknown
	}
	return dst
}

func visionTransportLifecycleRank(state VisionTransportLifecycleState) int {
	switch state {
	case VisionTransportLifecycleKTLSEnabled:
		return 3
	case VisionTransportLifecycleDeferredDetach:
		return 2
	case VisionTransportLifecycleDeferredActive:
		return 1
	default:
		return 0
	}
}

func mergeVisionTransportDetachStatus(dst VisionTransportDetachStatus, src VisionTransportDetachStatus) VisionTransportDetachStatus {
	switch {
	case src == "" || src == VisionTransportDetachStatusNone:
		if dst == "" {
			return VisionTransportDetachStatusNone
		}
		return dst
	case dst == "" || dst == VisionTransportDetachStatusNone:
		return src
	case dst == src:
		return dst
	default:
		return VisionTransportDetachStatusMixed
	}
}

func mergeVisionTransportKTLSPromotion(dst VisionTransportKTLSPromotion, src VisionTransportKTLSPromotion) VisionTransportKTLSPromotion {
	switch {
	case src == "" || src == VisionTransportKTLSPromotionNone:
		if dst == "" {
			return VisionTransportKTLSPromotionNone
		}
		return dst
	case dst == "" || dst == VisionTransportKTLSPromotionNone:
		return src
	case dst == src:
		return dst
	default:
		return VisionTransportKTLSPromotionMixed
	}
}

func mergeVisionDrainRelation(dst VisionDrainRelation, src VisionDrainRelation) VisionDrainRelation {
	switch {
	case src == "" || src == VisionDrainRelationNone:
		if dst == "" {
			return VisionDrainRelationNone
		}
		return dst
	case dst == "" || dst == VisionDrainRelationNone:
		return src
	case dst == src:
		return dst
	default:
		return VisionDrainRelationMismatch
	}
}

func deriveVisionDrainRelation(summary VisionTransitionSummary) VisionDrainRelation {
	accepted := summary.DrainCount > 0
	transport := summary.TransportDrainCount > 0
	switch {
	case !accepted && !transport:
		return VisionDrainRelationNone
	case accepted && !transport:
		return VisionDrainRelationAcceptedOnly
	case !accepted && transport:
		return VisionDrainRelationTransportOnly
	case summary.DrainMode == summary.TransportDrainMode &&
		summary.DrainCount == summary.TransportDrainCount &&
		summary.DrainPlaintextBytes == summary.TransportDrainPlaintextLen &&
		summary.DrainRawAheadBytes == summary.TransportDrainRawAheadLen:
		return VisionDrainRelationAligned
	default:
		return VisionDrainRelationMismatch
	}
}

func mergeVisionBridgeAssessment(dst VisionBridgeAssessment, src VisionBridgeAssessment) VisionBridgeAssessment {
	switch {
	case src == "" || src == VisionBridgeAssessmentNone:
		if dst == "" {
			return VisionBridgeAssessmentNone
		}
		return dst
	case dst == "" || dst == VisionBridgeAssessmentNone:
		return src
	case dst == src:
		return dst
	default:
		if visionBridgeAssessmentRank(src) > visionBridgeAssessmentRank(dst) {
			return src
		}
		return dst
	}
}

func mergeVisionPendingQuality(dst VisionPendingQuality, src VisionPendingQuality) VisionPendingQuality {
	switch {
	case src == "" || src == VisionPendingQualityNone:
		if dst == "" {
			return VisionPendingQualityNone
		}
		return dst
	case dst == "" || dst == VisionPendingQualityNone:
		return src
	case dst == src:
		return dst
	default:
		if visionPendingQualityRank(src) > visionPendingQualityRank(dst) {
			return src
		}
		return dst
	}
}

func visionBridgeAssessmentRank(assessment VisionBridgeAssessment) int {
	switch assessment {
	case VisionBridgeAssessmentNativeDetachFailed:
		return 5
	case VisionBridgeAssessmentNativeDivergent:
		return 4
	case VisionBridgeAssessmentNativeAligned:
		return 3
	case VisionBridgeAssessmentNativePending:
		return 2
	case VisionBridgeAssessmentGoBaseline:
		return 1
	default:
		return 0
	}
}

func visionPendingQualityRank(quality VisionPendingQuality) int {
	switch quality {
	case VisionPendingQualityFailure:
		return 2
	case VisionPendingQualityBenign:
		return 1
	default:
		return 0
	}
}

func mergeVisionPendingClass(dst VisionPendingClass, src VisionPendingClass) VisionPendingClass {
	switch {
	case src == "" || src == VisionPendingClassNone:
		if dst == "" {
			return VisionPendingClassNone
		}
		return dst
	case dst == "" || dst == VisionPendingClassNone:
		return src
	case dst == src:
		return dst
	default:
		if visionPendingClassRank(src) > visionPendingClassRank(dst) {
			return src
		}
		return dst
	}
}

func mergeVisionPendingGap(dst VisionPendingGap, src VisionPendingGap) VisionPendingGap {
	switch {
	case src == "" || src == VisionPendingGapNone:
		if dst == "" {
			return VisionPendingGapNone
		}
		return dst
	case dst == "" || dst == VisionPendingGapNone:
		return src
	case dst == src:
		return dst
	default:
		if visionPendingGapRank(src) > visionPendingGapRank(dst) {
			return src
		}
		return dst
	}
}

func mergeVisionNativeProvisionalSemantic(dst VisionNativeProvisionalSemantic, src VisionNativeProvisionalSemantic) VisionNativeProvisionalSemantic {
	switch {
	case src == "" || src == VisionNativeProvisionalSemanticNone:
		if dst == "" {
			return VisionNativeProvisionalSemanticNone
		}
		return dst
	case dst == "" || dst == VisionNativeProvisionalSemanticNone:
		return src
	case dst == src:
		return dst
	default:
		if visionNativeProvisionalSemanticRank(src) > visionNativeProvisionalSemanticRank(dst) {
			return src
		}
		return dst
	}
}

func mergeVisionNativeProvisionalSemanticSource(dst VisionNativeProvisionalSemanticSource, src VisionNativeProvisionalSemanticSource) VisionNativeProvisionalSemanticSource {
	switch {
	case src == "" || src == VisionNativeProvisionalSemanticSourceNone:
		if dst == "" {
			return VisionNativeProvisionalSemanticSourceNone
		}
		return dst
	case dst == "" || dst == VisionNativeProvisionalSemanticSourceNone:
		return src
	case dst == src:
		return dst
	default:
		if visionNativeProvisionalSemanticSourceRank(src) > visionNativeProvisionalSemanticSourceRank(dst) {
			return src
		}
		return dst
	}
}

func mergeVisionNativeProvisionalOutcome(dst VisionNativeProvisionalOutcome, src VisionNativeProvisionalOutcome) VisionNativeProvisionalOutcome {
	switch {
	case src == "" || src == VisionNativeProvisionalOutcomeNone:
		if dst == "" {
			return VisionNativeProvisionalOutcomeNone
		}
		return dst
	case dst == "" || dst == VisionNativeProvisionalOutcomeNone:
		return src
	case dst == src:
		return dst
	default:
		if visionNativeProvisionalOutcomeRank(src) > visionNativeProvisionalOutcomeRank(dst) {
			return src
		}
		return dst
	}
}

func mergeVisionNativeProvisionalTerminalReason(dst VisionNativeProvisionalTerminalReason, src VisionNativeProvisionalTerminalReason) VisionNativeProvisionalTerminalReason {
	switch {
	case src == "" || src == VisionNativeProvisionalTerminalReasonNone:
		if dst == "" {
			return VisionNativeProvisionalTerminalReasonNone
		}
		return dst
	case dst == "" || dst == VisionNativeProvisionalTerminalReasonNone:
		return src
	case dst == src:
		return dst
	default:
		if visionNativeProvisionalTerminalReasonRank(src) > visionNativeProvisionalTerminalReasonRank(dst) {
			return src
		}
		return dst
	}
}

func mergeVisionTransportProgress(dst VisionTransportProgressProfile, src VisionTransportProgressProfile) VisionTransportProgressProfile {
	switch {
	case src == "" || src == VisionTransportProgressNone:
		if dst == "" {
			return VisionTransportProgressNone
		}
		return dst
	case dst == "" || dst == VisionTransportProgressNone:
		return src
	case dst == src:
		return dst
	default:
		return VisionTransportProgressBidirectional
	}
}

func visionPendingClassRank(class VisionPendingClass) int {
	switch class {
	case VisionPendingClassCommand0Only:
		return 4
	case VisionPendingClassExplicitNoDetach:
		return 3
	case VisionPendingClassPayloadBypass:
		return 2
	case VisionPendingClassOther:
		return 1
	default:
		return 0
	}
}

func visionPendingGapRank(gap VisionPendingGap) int {
	switch gap {
	case VisionPendingGapCommand0BidirectionalNoDet:
		return 2
	case VisionPendingGapOther:
		return 1
	default:
		return 0
	}
}

func visionNativeProvisionalSemanticRank(semantic VisionNativeProvisionalSemantic) int {
	switch semantic {
	case VisionNativeProvisionalSemanticCommand0Bidirectional:
		return 1
	default:
		return 0
	}
}

func visionNativeProvisionalSemanticSourceRank(source VisionNativeProvisionalSemanticSource) int {
	switch source {
	case VisionNativeProvisionalSemanticSourceExplicitProducer:
		return 5
	case VisionNativeProvisionalSemanticSourceTransportProducer:
		return 4
	case VisionNativeProvisionalSemanticSourceBridgeProducer:
		return 3
	case VisionNativeProvisionalSemanticSourceDerived:
		return 2
	default:
		return 0
	}
}

func isVisionNativeProvisionalProducerSource(source VisionNativeProvisionalSemanticSource) bool {
	switch source {
	case VisionNativeProvisionalSemanticSourceTransportProducer, VisionNativeProvisionalSemanticSourceBridgeProducer, VisionNativeProvisionalSemanticSourceExplicitProducer:
		return true
	default:
		return false
	}
}

func isVisionNativeProvisionalTransportSource(source VisionNativeProvisionalSemanticSource) bool {
	return source == VisionNativeProvisionalSemanticSourceTransportProducer
}

func visionNativeProvisionalOutcomeRank(outcome VisionNativeProvisionalOutcome) int {
	switch outcome {
	case VisionNativeProvisionalOutcomeFailedPending:
		return 5
	case VisionNativeProvisionalOutcomeResolvedDirect:
		return 4
	case VisionNativeProvisionalOutcomeResolvedNoDetach:
		return 3
	case VisionNativeProvisionalOutcomeBenignClose:
		return 2
	case VisionNativeProvisionalOutcomeActive:
		return 1
	default:
		return 0
	}
}

func mergeVisionNativeProvisionalOutcomeSource(dst VisionNativeProvisionalOutcomeSource, src VisionNativeProvisionalOutcomeSource) VisionNativeProvisionalOutcomeSource {
	switch {
	case src == "" || src == VisionNativeProvisionalOutcomeSourceNone:
		if dst == "" {
			return VisionNativeProvisionalOutcomeSourceNone
		}
		return dst
	case dst == "" || dst == VisionNativeProvisionalOutcomeSourceNone:
		return src
	default:
		if visionNativeProvisionalOutcomeSourceRank(src) > visionNativeProvisionalOutcomeSourceRank(dst) {
			return src
		}
		return dst
	}
}

func visionNativeProvisionalOutcomeSourceRank(source VisionNativeProvisionalOutcomeSource) int {
	switch source {
	case VisionNativeProvisionalOutcomeSourceExplicitProducer:
		return 5
	case VisionNativeProvisionalOutcomeSourceTransportProducer:
		return 4
	case VisionNativeProvisionalOutcomeSourceBridgeProducer:
		return 3
	case VisionNativeProvisionalOutcomeSourceDerived:
		return 2
	default:
		return 0
	}
}

func isVisionNativeProvisionalOutcomeProducerSource(source VisionNativeProvisionalOutcomeSource) bool {
	switch source {
	case VisionNativeProvisionalOutcomeSourceTransportProducer, VisionNativeProvisionalOutcomeSourceBridgeProducer, VisionNativeProvisionalOutcomeSourceExplicitProducer:
		return true
	default:
		return false
	}
}

func isVisionNativeProvisionalOutcomeTransportOwnedSource(source VisionNativeProvisionalOutcomeSource) bool {
	switch source {
	case VisionNativeProvisionalOutcomeSourceTransportProducer, VisionNativeProvisionalOutcomeSourceExplicitProducer:
		return true
	default:
		return false
	}
}

func visionNativeProvisionalTerminalReasonRank(reason VisionNativeProvisionalTerminalReason) int {
	switch reason {
	case VisionNativeProvisionalTerminalReasonReset,
		VisionNativeProvisionalTerminalReasonBrokenPipe,
		VisionNativeProvisionalTerminalReasonBadMessage,
		VisionNativeProvisionalTerminalReasonEIO:
		return 4
	case VisionNativeProvisionalTerminalReasonEOF,
		VisionNativeProvisionalTerminalReasonClosed,
		VisionNativeProvisionalTerminalReasonLocalClose:
		return 3
	case VisionNativeProvisionalTerminalReasonOther:
		return 1
	default:
		return 0
	}
}

func deriveVisionBridgeAssessment(summary VisionTransitionSummary) VisionBridgeAssessment {
	if summary.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		if summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown {
			return VisionBridgeAssessmentNone
		}
		return VisionBridgeAssessmentGoBaseline
	}
	switch {
	case summary.TransportDetachStatus == VisionTransportDetachStatusFailed:
		return VisionBridgeAssessmentNativeDetachFailed
	case summary.DrainRelation == VisionDrainRelationAligned:
		return VisionBridgeAssessmentNativeAligned
	case summary.DrainRelation == VisionDrainRelationAcceptedOnly ||
		summary.DrainRelation == VisionDrainRelationTransportOnly ||
		summary.DrainRelation == VisionDrainRelationMismatch:
		return VisionBridgeAssessmentNativeDivergent
	case summary.TransportLifecycleState != VisionTransportLifecycleUnknown ||
		summary.TransportDetachStatus != VisionTransportDetachStatusNone ||
		summary.TransportKTLSPromotion != VisionTransportKTLSPromotionNone:
		return VisionBridgeAssessmentNativePending
	default:
		return VisionBridgeAssessmentNativePending
	}
}

func deriveVisionPendingQuality(summary VisionTransitionSummary, snap *pipeline.DecisionSnapshot) VisionPendingQuality {
	if summary.BridgeAssessment != VisionBridgeAssessmentNativePending || snap == nil {
		return VisionPendingQualityNone
	}
	if snap.UserspaceBytes == 0 {
		switch snap.UserspaceExit {
		case pipeline.UserspaceExitTimeout, pipeline.UserspaceExitLocalCloseNoResponse:
			return VisionPendingQualityFailure
		}
	}
	switch snap.Reason {
	case pipeline.ReasonControlPlaneDNSGuard, pipeline.ReasonLoopbackDNSGuard:
		if snap.UserspaceExit == pipeline.UserspaceExitComplete {
			return VisionPendingQualityBenign
		}
	case pipeline.ReasonVisionNoDetachUserspace, pipeline.ReasonVisionControlUserspace:
		if snap.UserspaceExit == pipeline.UserspaceExitStableUserspaceClose ||
			snap.UserspaceExit == pipeline.UserspaceExitComplete ||
			snap.UserspaceExit == pipeline.UserspaceExitNone {
			return VisionPendingQualityBenign
		}
	}
	if snap.UserspaceBytes > 0 {
		switch snap.UserspaceExit {
		case pipeline.UserspaceExitStableUserspaceClose, pipeline.UserspaceExitComplete, pipeline.UserspaceExitNone:
			return VisionPendingQualityBenign
		}
	}
	return VisionPendingQualityNone
}

func deriveVisionPendingClass(summary VisionTransitionSummary) VisionPendingClass {
	if summary.BridgeAssessment != VisionBridgeAssessmentNativePending {
		return VisionPendingClassNone
	}
	if summary.Uplink.Command2Count > 0 {
		return VisionPendingClassOther
	}
	if summary.Uplink.Command1Count > 0 || summary.Uplink.Semantic == VisionSemanticExplicitNoDetach {
		return VisionPendingClassExplicitNoDetach
	}
	if summary.Uplink.PayloadBypass || summary.Uplink.Semantic == VisionSemanticPayloadBypass {
		return VisionPendingClassPayloadBypass
	}
	if summary.Uplink.Command0Count > 0 && summary.Uplink.Command1Count == 0 && summary.Uplink.Command2Count == 0 && summary.Uplink.Semantic == VisionSemanticUnknown {
		return VisionPendingClassCommand0Only
	}
	return VisionPendingClassOther
}

func deriveVisionPendingGap(summary VisionTransitionSummary) VisionPendingGap {
	if summary.BridgeAssessment != VisionBridgeAssessmentNativePending {
		return VisionPendingGapNone
	}
	if summary.NativeProvisionalSemantic == VisionNativeProvisionalSemanticCommand0Bidirectional {
		return VisionPendingGapCommand0BidirectionalNoDet
	}
	if summary.PendingClass == VisionPendingClassCommand0Only &&
		summary.TransportProgress == VisionTransportProgressBidirectional &&
		summary.TransportDetachStatus == VisionTransportDetachStatusNone &&
		summary.DrainRelation == VisionDrainRelationNone {
		return VisionPendingGapCommand0BidirectionalNoDet
	}
	if summary.PendingClass != VisionPendingClassNone {
		return VisionPendingGapOther
	}
	return VisionPendingGapNone
}

func deriveVisionNativeProvisionalSemantic(summary VisionTransitionSummary) VisionNativeProvisionalSemantic {
	if shouldPromoteVisionNativeProvisionalSemantic(summary) {
		return VisionNativeProvisionalSemanticCommand0Bidirectional
	}
	return VisionNativeProvisionalSemanticNone
}

func latchVisionNativeProvisionalObservation(summary *VisionTransitionSummary) {
	if summary == nil {
		return
	}
	if summary.NativeProvisionalSemantic == VisionNativeProvisionalSemanticNone {
		return
	}
	summary.NativeProvisionalObserved = mergeVisionNativeProvisionalSemantic(summary.NativeProvisionalObserved, summary.NativeProvisionalSemantic)
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceNone {
		summary.NativeProvisionalObservedSource = mergeVisionNativeProvisionalSemanticSource(summary.NativeProvisionalObservedSource, summary.NativeProvisionalSource)
	}
}

func deriveVisionNativeProvisionalOutcome(summary VisionTransitionSummary) VisionNativeProvisionalOutcome {
	if summary.NativeProvisionalObserved == VisionNativeProvisionalSemanticNone {
		return VisionNativeProvisionalOutcomeNone
	}
	if summary.Uplink.Semantic == VisionSemanticExplicitDirect || summary.Downlink.Semantic == VisionSemanticExplicitDirect || summary.BridgeAssessment == VisionBridgeAssessmentNativeAligned || summary.DrainRelation == VisionDrainRelationAligned {
		return VisionNativeProvisionalOutcomeResolvedDirect
	}
	if summary.Uplink.Semantic == VisionSemanticExplicitNoDetach || summary.Downlink.Semantic == VisionSemanticExplicitNoDetach || summary.PendingClass == VisionPendingClassExplicitNoDetach {
		return VisionNativeProvisionalOutcomeResolvedNoDetach
	}
	switch summary.PendingQuality {
	case VisionPendingQualityBenign:
		return VisionNativeProvisionalOutcomeBenignClose
	case VisionPendingQualityFailure:
		return VisionNativeProvisionalOutcomeFailedPending
	}
	if summary.NativeProvisionalSemantic != VisionNativeProvisionalSemanticNone {
		return VisionNativeProvisionalOutcomeActive
	}
	return VisionNativeProvisionalOutcomeActive
}

func applyVisionProvisionalOutcomeToPending(summary *VisionTransitionSummary) {
	if summary == nil {
		return
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional ||
		!isVisionNativeProvisionalProducerSource(summary.NativeProvisionalObservedSource) {
		return
	}
	switch summary.NativeProvisionalOutcome {
	case VisionNativeProvisionalOutcomeResolvedNoDetach:
		summary.PendingQuality = VisionPendingQualityBenign
		summary.PendingClass = VisionPendingClassExplicitNoDetach
		summary.PendingGap = VisionPendingGapOther
	case VisionNativeProvisionalOutcomeBenignClose:
		summary.PendingQuality = VisionPendingQualityBenign
		summary.PendingClass = VisionPendingClassCommand0Only
		summary.PendingGap = VisionPendingGapCommand0BidirectionalNoDet
	case VisionNativeProvisionalOutcomeFailedPending:
		summary.PendingQuality = VisionPendingQualityFailure
		summary.PendingClass = VisionPendingClassCommand0Only
		summary.PendingGap = VisionPendingGapCommand0BidirectionalNoDet
	case VisionNativeProvisionalOutcomeActive:
		summary.PendingClass = VisionPendingClassCommand0Only
		summary.PendingGap = VisionPendingGapCommand0BidirectionalNoDet
	}
}

func normalizeVisionTransportOwnedTerminalOutcome(summary *VisionTransitionSummary, snap *pipeline.DecisionSnapshot, final bool) {
	if summary == nil || !final {
		return
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional ||
		!isVisionNativeProvisionalTransportSource(summary.NativeProvisionalObservedSource) {
		return
	}
	switch summary.NativeProvisionalOutcome {
	case VisionNativeProvisionalOutcomeResolvedDirect, VisionNativeProvisionalOutcomeResolvedNoDetach, VisionNativeProvisionalOutcomeTerminatedPending:
		return
	}
	switch summary.PendingQuality {
	case VisionPendingQualityFailure:
		transportOwned := isVisionNativeProvisionalOutcomeTransportOwnedSource(summary.NativeProvisionalOutcomeSource)
		terminalReason := deriveVisionPendingTerminalReasonFromDecision(snap, VisionPendingQualityFailure)
		summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeFailedPending
		summary.NativeProvisionalOutcomeSource = visionPendingTerminalOutcomeSource(terminalReason)
		if terminalReason == VisionNativeProvisionalTerminalReasonLocalClose || !transportOwned || summary.NativeProvisionalTerminalReason == VisionNativeProvisionalTerminalReasonNone || summary.NativeProvisionalTerminalReason == VisionNativeProvisionalTerminalReasonOther {
			summary.NativeProvisionalTerminalReason = terminalReason
		}
	case VisionPendingQualityBenign:
		transportOwned := isVisionNativeProvisionalOutcomeTransportOwnedSource(summary.NativeProvisionalOutcomeSource)
		terminalReason := deriveVisionPendingTerminalReasonFromDecision(snap, VisionPendingQualityBenign)
		summary.NativeProvisionalOutcome = VisionNativeProvisionalOutcomeBenignClose
		summary.NativeProvisionalOutcomeSource = visionPendingTerminalOutcomeSource(terminalReason)
		if terminalReason == VisionNativeProvisionalTerminalReasonLocalClose || !transportOwned || summary.NativeProvisionalTerminalReason == VisionNativeProvisionalTerminalReasonNone || summary.NativeProvisionalTerminalReason == VisionNativeProvisionalTerminalReasonOther {
			summary.NativeProvisionalTerminalReason = terminalReason
		}
	}
}

func normalizeVisionBridgeOwnedTerminalOutcome(summary *VisionTransitionSummary, snap *pipeline.DecisionSnapshot, final bool) {
	if summary == nil || !final {
		return
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceBridgeProducer {
		return
	}
	switch summary.NativeProvisionalOutcome {
	case VisionNativeProvisionalOutcomeFailedPending:
		summary.NativeProvisionalTerminalReason = deriveVisionPendingTerminalReasonFromDecision(snap, VisionPendingQualityFailure)
	case VisionNativeProvisionalOutcomeBenignClose:
		summary.NativeProvisionalTerminalReason = deriveVisionPendingTerminalReasonFromDecision(snap, VisionPendingQualityBenign)
	}
}

func enforceVisionBridgeOwnedLocalTerminalReason(summary *VisionTransitionSummary, snap *pipeline.DecisionSnapshot, final bool) {
	if summary == nil || !final {
		return
	}
	var pendingQuality VisionPendingQuality
	switch summary.NativeProvisionalOutcome {
	case VisionNativeProvisionalOutcomeFailedPending:
		pendingQuality = VisionPendingQualityFailure
	case VisionNativeProvisionalOutcomeBenignClose:
		pendingQuality = VisionPendingQualityBenign
	default:
		return
	}
	if deriveVisionPendingTerminalReasonFromDecision(snap, pendingQuality) != VisionNativeProvisionalTerminalReasonLocalClose {
		return
	}
	summary.NativeProvisionalOutcomeSource = VisionNativeProvisionalOutcomeSourceBridgeProducer
	summary.NativeProvisionalTerminalReason = VisionNativeProvisionalTerminalReasonLocalClose
}

func shouldPromoteVisionNativeProvisionalSemantic(summary VisionTransitionSummary) bool {
	if summary.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		return false
	}
	if summary.Uplink.Semantic != VisionSemanticUnknown ||
		summary.Uplink.Command1Count > 0 ||
		summary.Uplink.Command2Count > 0 {
		return false
	}
	if summary.Uplink.Command0Count > 0 &&
		deriveVisionTransportProgress(summary) == VisionTransportProgressBidirectional &&
		summary.TransportDetachStatus == VisionTransportDetachStatusNone &&
		summary.DrainCount == 0 &&
		summary.TransportDrainCount == 0 {
		return true
	}
	return false
}

func deriveVisionTransportProgress(summary VisionTransitionSummary) VisionTransportProgressProfile {
	switch {
	case summary.TransportReadOps > 0 && summary.TransportWriteOps > 0:
		return VisionTransportProgressBidirectional
	case summary.TransportWriteOps > 0:
		return VisionTransportProgressWriteOnly
	case summary.TransportReadOps > 0:
		return VisionTransportProgressReadOnly
	default:
		return VisionTransportProgressNone
	}
}

func observeVisionBridgeAssessment(scope string, assessment VisionBridgeAssessment, pendingQuality VisionPendingQuality, pendingClass VisionPendingClass, pendingGap VisionPendingGap, nativeProvisionalObserved VisionNativeProvisionalSemantic, nativeProvisionalObservedSource VisionNativeProvisionalSemanticSource, nativeProvisionalOutcome VisionNativeProvisionalOutcome, nativeProvisionalOutcomeSource VisionNativeProvisionalOutcomeSource, nativeProvisionalTerminalReason VisionNativeProvisionalTerminalReason) {
	if assessment == "" || assessment == VisionBridgeAssessmentNone {
		return
	}
	scope = normalizeVisionBridgeAssessmentScope(scope)
	window := ensureVisionBridgeAssessmentWindow(scope)
	if window == nil {
		return
	}
	window.observe(visionBridgeAssessmentNowFn(), assessment, pendingQuality, pendingClass, pendingGap, nativeProvisionalObserved, nativeProvisionalObservedSource, nativeProvisionalOutcome, nativeProvisionalOutcomeSource, nativeProvisionalTerminalReason)
	observeVisionBridgeProbeAssessment(scope, assessment, pendingQuality, pendingClass, pendingGap, nativeProvisionalObserved, nativeProvisionalObservedSource, nativeProvisionalOutcome, nativeProvisionalOutcomeSource, nativeProvisionalTerminalReason)
}

func resetVisionBridgeAssessmentStatsForTest() {
	visionBridgeAssessmentStatsByScope = sync.Map{}
	visionBridgeAssessmentNowFn = time.Now
	visionBridgeAssessmentBucketWidth = time.Minute
}

func resetVisionBridgeProbeEpochsForTest() {
	visionBridgeProbeEpochByScope = sync.Map{}
	visionBridgeProbeNowFn = time.Now
}

func normalizeVisionBridgeAssessmentScope(scope string) string {
	if scope == "" {
		return visionBridgeAssessmentUnscopedKey
	}
	return scope
}

func ensureVisionBridgeAssessmentWindow(scope string) *visionBridgeAssessmentWindow {
	value, _ := visionBridgeAssessmentStatsByScope.LoadOrStore(scope, newVisionBridgeAssessmentWindow(visionBridgeAssessmentNowFn()))
	window, _ := value.(*visionBridgeAssessmentWindow)
	return window
}

func ensureVisionBridgeProbeEpoch(scope string) *visionBridgeProbeEpoch {
	value, _ := visionBridgeProbeEpochByScope.LoadOrStore(scope, &visionBridgeProbeEpoch{
		scopeKey: scope,
		state:    VisionBridgeProbeStateInactive,
		verdict:  VisionBridgeProbeVerdictNone,
	})
	epoch, _ := value.(*visionBridgeProbeEpoch)
	return epoch
}

func loadVisionBridgeAssessmentWindow(scope string) *visionBridgeAssessmentWindow {
	value, ok := visionBridgeAssessmentStatsByScope.Load(scope)
	if !ok {
		return nil
	}
	window, _ := value.(*visionBridgeAssessmentWindow)
	return window
}

func loadVisionBridgeProbeEpoch(scope string) *visionBridgeProbeEpoch {
	value, ok := visionBridgeProbeEpochByScope.Load(scope)
	if !ok {
		return nil
	}
	epoch, _ := value.(*visionBridgeProbeEpoch)
	return epoch
}

func newVisionBridgeAssessmentWindow(now time.Time) *visionBridgeAssessmentWindow {
	return &visionBridgeAssessmentWindow{
		startBucket: alignedVisionBridgeAssessmentBucket(now) - int64(visionBridgeAssessmentBucketCount-1)*visionBridgeAssessmentBucketWidth.Nanoseconds(),
	}
}

func (w *visionBridgeAssessmentWindow) observe(now time.Time, assessment VisionBridgeAssessment, pendingQuality VisionPendingQuality, pendingClass VisionPendingClass, pendingGap VisionPendingGap, nativeProvisionalObserved VisionNativeProvisionalSemantic, nativeProvisionalObservedSource VisionNativeProvisionalSemanticSource, nativeProvisionalOutcome VisionNativeProvisionalOutcome, nativeProvisionalOutcomeSource VisionNativeProvisionalOutcomeSource, nativeProvisionalTerminalReason VisionNativeProvisionalTerminalReason) {
	w.mu.Lock()
	defer w.mu.Unlock()

	idx := w.bucketIndexLocked(now)
	if nativeProvisionalObserved == VisionNativeProvisionalSemanticCommand0Bidirectional &&
		isVisionNativeProvisionalTransportSource(nativeProvisionalObservedSource) {
		w.nativeProvisionalCommand0Bidirectional[idx]++
		switch nativeProvisionalOutcome {
		case VisionNativeProvisionalOutcomeActive:
			w.nativeProvisionalActive[idx]++
		case VisionNativeProvisionalOutcomeTerminatedPending:
			w.nativeProvisionalTerminatedPending[idx]++
		case VisionNativeProvisionalOutcomeResolvedDirect:
			w.nativeProvisionalResolvedDirect[idx]++
		case VisionNativeProvisionalOutcomeResolvedNoDetach:
			w.nativeProvisionalResolvedNoDetach[idx]++
		case VisionNativeProvisionalOutcomeBenignClose:
			if isVisionNativeProvisionalOutcomeTransportOwnedSource(nativeProvisionalOutcomeSource) {
				w.nativeProvisionalBenignClose[idx]++
			}
		case VisionNativeProvisionalOutcomeFailedPending:
			if isVisionNativeProvisionalOutcomeTransportOwnedSource(nativeProvisionalOutcomeSource) ||
				nativeProvisionalTerminalReason == VisionNativeProvisionalTerminalReasonLocalClose {
				w.nativeProvisionalFailedPending[idx]++
				switch nativeProvisionalTerminalReason {
				case VisionNativeProvisionalTerminalReasonLocalClose:
					w.nativeProvisionalFailedPendingLocalClose[idx]++
				case VisionNativeProvisionalTerminalReasonEOF:
					w.nativeProvisionalFailedPendingEOF[idx]++
				case VisionNativeProvisionalTerminalReasonClosed:
					w.nativeProvisionalFailedPendingClosed[idx]++
				case VisionNativeProvisionalTerminalReasonReset:
					w.nativeProvisionalFailedPendingReset[idx]++
				case VisionNativeProvisionalTerminalReasonBrokenPipe:
					w.nativeProvisionalFailedPendingBrokenPipe[idx]++
				case VisionNativeProvisionalTerminalReasonBadMessage:
					w.nativeProvisionalFailedPendingBadMessage[idx]++
				case VisionNativeProvisionalTerminalReasonEIO:
					w.nativeProvisionalFailedPendingEIO[idx]++
				default:
					w.nativeProvisionalFailedPendingOther[idx]++
				}
			}
		}
	}
	switch assessment {
	case VisionBridgeAssessmentGoBaseline:
		w.goBaseline[idx]++
	case VisionBridgeAssessmentNativePending:
		w.nativePending[idx]++
		switch pendingQuality {
		case VisionPendingQualityBenign:
			w.nativePendingBenign[idx]++
		case VisionPendingQualityFailure:
			w.nativePendingFailure[idx]++
			if nativeProvisionalObserved == VisionNativeProvisionalSemanticCommand0Bidirectional &&
				isVisionNativeProvisionalTransportSource(nativeProvisionalObservedSource) &&
				isVisionNativeProvisionalOutcomeTransportOwnedSource(nativeProvisionalOutcomeSource) {
				w.nativeProvisionalCommand0BidirectionalFailure[idx]++
			}
			if pendingClass == VisionPendingClassCommand0Only {
				w.nativePendingCommand0Failure[idx]++
			}
			if pendingGap == VisionPendingGapCommand0BidirectionalNoDet {
				w.nativePendingCommand0BidirectionalFailure[idx]++
			}
		}
	case VisionBridgeAssessmentNativeAligned:
		w.nativeAligned[idx]++
	case VisionBridgeAssessmentNativeDivergent:
		w.nativeDivergent[idx]++
	case VisionBridgeAssessmentNativeDetachFailed:
		w.nativeDetachFailed[idx]++
	}
}

func (w *visionBridgeAssessmentWindow) snapshot(now time.Time) VisionBridgeAssessmentStats {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.bucketIndexLocked(now)
	return VisionBridgeAssessmentStats{
		GoBaseline:                             sumVisionBridgeAssessmentBuckets(w.goBaseline[:]),
		NativePending:                          sumVisionBridgeAssessmentBuckets(w.nativePending[:]),
		NativePendingBenign:                    sumVisionBridgeAssessmentBuckets(w.nativePendingBenign[:]),
		NativePendingFailure:                   sumVisionBridgeAssessmentBuckets(w.nativePendingFailure[:]),
		NativeProvisionalCommand0Bidirectional: sumVisionBridgeAssessmentBuckets(w.nativeProvisionalCommand0Bidirectional[:]),
		NativeProvisionalCommand0BidirectionalFailure: sumVisionBridgeAssessmentBuckets(w.nativeProvisionalCommand0BidirectionalFailure[:]),
		NativeProvisionalActive:                       sumVisionBridgeAssessmentBuckets(w.nativeProvisionalActive[:]),
		NativeProvisionalTerminatedPending:            sumVisionBridgeAssessmentBuckets(w.nativeProvisionalTerminatedPending[:]),
		NativeProvisionalResolvedDirect:               sumVisionBridgeAssessmentBuckets(w.nativeProvisionalResolvedDirect[:]),
		NativeProvisionalResolvedNoDetach:             sumVisionBridgeAssessmentBuckets(w.nativeProvisionalResolvedNoDetach[:]),
		NativeProvisionalBenignClose:                  sumVisionBridgeAssessmentBuckets(w.nativeProvisionalBenignClose[:]),
		NativeProvisionalFailedPending:                sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPending[:]),
		NativeProvisionalFailedPendingLocalClose:      sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingLocalClose[:]),
		NativeProvisionalFailedPendingEOF:             sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingEOF[:]),
		NativeProvisionalFailedPendingClosed:          sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingClosed[:]),
		NativeProvisionalFailedPendingReset:           sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingReset[:]),
		NativeProvisionalFailedPendingBrokenPipe:      sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingBrokenPipe[:]),
		NativeProvisionalFailedPendingBadMessage:      sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingBadMessage[:]),
		NativeProvisionalFailedPendingEIO:             sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingEIO[:]),
		NativeProvisionalFailedPendingOther:           sumVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingOther[:]),
		NativePendingCommand0Failure:                  sumVisionBridgeAssessmentBuckets(w.nativePendingCommand0Failure[:]),
		NativePendingCommand0BidirectionalFailure:     sumVisionBridgeAssessmentBuckets(w.nativePendingCommand0BidirectionalFailure[:]),
		NativeAligned:      sumVisionBridgeAssessmentBuckets(w.nativeAligned[:]),
		NativeDivergent:    sumVisionBridgeAssessmentBuckets(w.nativeDivergent[:]),
		NativeDetachFailed: sumVisionBridgeAssessmentBuckets(w.nativeDetachFailed[:]),
	}
}

func (w *visionBridgeAssessmentWindow) bucketIndexLocked(now time.Time) int {
	nowBucket := alignedVisionBridgeAssessmentBucket(now)
	w.advanceLocked(nowBucket)
	idx := int((nowBucket - w.startBucket) / visionBridgeAssessmentBucketWidth.Nanoseconds())
	if idx < 0 {
		return 0
	}
	if idx >= visionBridgeAssessmentBucketCount {
		return visionBridgeAssessmentBucketCount - 1
	}
	return idx
}

func (w *visionBridgeAssessmentWindow) advanceLocked(nowBucket int64) {
	width := visionBridgeAssessmentBucketWidth.Nanoseconds()
	if width <= 0 {
		width = time.Minute.Nanoseconds()
	}
	if w.startBucket == 0 {
		w.startBucket = nowBucket - int64(visionBridgeAssessmentBucketCount-1)*width
		return
	}
	newestBucket := w.startBucket + int64(visionBridgeAssessmentBucketCount-1)*width
	if nowBucket <= newestBucket {
		return
	}
	shift := int((nowBucket - newestBucket) / width)
	if shift >= visionBridgeAssessmentBucketCount {
		w.resetBucketsLocked()
		w.startBucket = nowBucket - int64(visionBridgeAssessmentBucketCount-1)*width
		return
	}
	w.shiftBucketsLocked(shift)
	w.startBucket += int64(shift) * width
}

func (w *visionBridgeAssessmentWindow) resetBucketsLocked() {
	w.goBaseline = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativePending = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativePendingBenign = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativePendingFailure = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalCommand0Bidirectional = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalCommand0BidirectionalFailure = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalActive = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalTerminatedPending = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalResolvedDirect = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalResolvedNoDetach = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalBenignClose = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPending = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPendingLocalClose = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPendingEOF = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPendingClosed = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPendingReset = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPendingBrokenPipe = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPendingBadMessage = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPendingEIO = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeProvisionalFailedPendingOther = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativePendingCommand0Failure = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativePendingCommand0BidirectionalFailure = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeAligned = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeDivergent = [visionBridgeAssessmentBucketCount]uint64{}
	w.nativeDetachFailed = [visionBridgeAssessmentBucketCount]uint64{}
}

func (w *visionBridgeAssessmentWindow) shiftBucketsLocked(shift int) {
	shiftVisionBridgeAssessmentBuckets(w.goBaseline[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativePending[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativePendingBenign[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativePendingFailure[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalCommand0Bidirectional[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalCommand0BidirectionalFailure[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalActive[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalTerminatedPending[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalResolvedDirect[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalResolvedNoDetach[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalBenignClose[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPending[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingLocalClose[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingEOF[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingClosed[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingReset[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingBrokenPipe[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingBadMessage[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingEIO[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeProvisionalFailedPendingOther[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativePendingCommand0Failure[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativePendingCommand0BidirectionalFailure[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeAligned[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeDivergent[:], shift)
	shiftVisionBridgeAssessmentBuckets(w.nativeDetachFailed[:], shift)
}

func (e *visionBridgeProbeEpoch) ensure(now time.Time, budget uint64, duration time.Duration) VisionBridgeProbeSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.scopeKey == "" {
		e.scopeKey = visionBridgeAssessmentUnscopedKey
	}
	if budget == 0 {
		budget = 1
	}
	if duration <= 0 {
		duration = time.Minute
	}
	if e.state == "" {
		e.state = VisionBridgeProbeStateInactive
	}
	if e.state == VisionBridgeProbeStateInactive {
		e.state = VisionBridgeProbeStateActive
		e.verdict = VisionBridgeProbeVerdictNoSignal
		e.started = now
		e.deadline = now.Add(duration)
		e.budget = budget
		e.stats = VisionBridgeAssessmentStats{}
	}
	e.refreshLocked(now)
	return e.snapshotLocked(now)
}

func (e *visionBridgeProbeEpoch) snapshot(now time.Time) VisionBridgeProbeSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshLocked(now)
	return e.snapshotLocked(now)
}

func (e *visionBridgeProbeEpoch) observe(now time.Time, assessment VisionBridgeAssessment, pendingQuality VisionPendingQuality, pendingClass VisionPendingClass, pendingGap VisionPendingGap, nativeProvisionalObserved VisionNativeProvisionalSemantic, nativeProvisionalObservedSource VisionNativeProvisionalSemanticSource, nativeProvisionalOutcome VisionNativeProvisionalOutcome, nativeProvisionalOutcomeSource VisionNativeProvisionalOutcomeSource, nativeProvisionalTerminalReason VisionNativeProvisionalTerminalReason) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != VisionBridgeProbeStateActive {
		return
	}
	if nativeProvisionalObserved == VisionNativeProvisionalSemanticCommand0Bidirectional &&
		isVisionNativeProvisionalTransportSource(nativeProvisionalObservedSource) {
		e.stats.NativeProvisionalCommand0Bidirectional++
		switch nativeProvisionalOutcome {
		case VisionNativeProvisionalOutcomeActive:
			e.stats.NativeProvisionalActive++
		case VisionNativeProvisionalOutcomeTerminatedPending:
			e.stats.NativeProvisionalTerminatedPending++
		case VisionNativeProvisionalOutcomeResolvedDirect:
			e.stats.NativeProvisionalResolvedDirect++
		case VisionNativeProvisionalOutcomeResolvedNoDetach:
			e.stats.NativeProvisionalResolvedNoDetach++
		case VisionNativeProvisionalOutcomeBenignClose:
			if isVisionNativeProvisionalOutcomeTransportOwnedSource(nativeProvisionalOutcomeSource) {
				e.stats.NativeProvisionalBenignClose++
			}
		case VisionNativeProvisionalOutcomeFailedPending:
			if isVisionNativeProvisionalOutcomeTransportOwnedSource(nativeProvisionalOutcomeSource) {
				e.stats.NativeProvisionalFailedPending++
				switch nativeProvisionalTerminalReason {
				case VisionNativeProvisionalTerminalReasonEOF:
					e.stats.NativeProvisionalFailedPendingEOF++
				case VisionNativeProvisionalTerminalReasonClosed:
					e.stats.NativeProvisionalFailedPendingClosed++
				case VisionNativeProvisionalTerminalReasonReset:
					e.stats.NativeProvisionalFailedPendingReset++
				case VisionNativeProvisionalTerminalReasonBrokenPipe:
					e.stats.NativeProvisionalFailedPendingBrokenPipe++
				case VisionNativeProvisionalTerminalReasonBadMessage:
					e.stats.NativeProvisionalFailedPendingBadMessage++
				case VisionNativeProvisionalTerminalReasonEIO:
					e.stats.NativeProvisionalFailedPendingEIO++
				default:
					e.stats.NativeProvisionalFailedPendingOther++
				}
			}
		}
	}
	switch assessment {
	case VisionBridgeAssessmentGoBaseline:
		e.stats.GoBaseline++
	case VisionBridgeAssessmentNativePending:
		e.stats.NativePending++
		switch pendingQuality {
		case VisionPendingQualityBenign:
			e.stats.NativePendingBenign++
		case VisionPendingQualityFailure:
			e.stats.NativePendingFailure++
			if nativeProvisionalObserved == VisionNativeProvisionalSemanticCommand0Bidirectional &&
				isVisionNativeProvisionalTransportSource(nativeProvisionalObservedSource) &&
				isVisionNativeProvisionalOutcomeTransportOwnedSource(nativeProvisionalOutcomeSource) {
				e.stats.NativeProvisionalCommand0BidirectionalFailure++
			}
			if pendingClass == VisionPendingClassCommand0Only {
				e.stats.NativePendingCommand0Failure++
			}
			if pendingGap == VisionPendingGapCommand0BidirectionalNoDet {
				e.stats.NativePendingCommand0BidirectionalFailure++
			}
		}
	case VisionBridgeAssessmentNativeAligned:
		e.stats.NativeAligned++
	case VisionBridgeAssessmentNativeDivergent:
		e.stats.NativeDivergent++
	case VisionBridgeAssessmentNativeDetachFailed:
		e.stats.NativeDetachFailed++
	}
	e.refreshLocked(now)
}

func (e *visionBridgeProbeEpoch) refreshLocked(now time.Time) {
	if e.state == VisionBridgeProbeStateInactive {
		e.verdict = VisionBridgeProbeVerdictNone
		return
	}
	e.verdict = deriveVisionBridgeProbeVerdict(e.stats)
	if e.state != VisionBridgeProbeStateActive {
		return
	}
	if nativeObservedVisionBridgeAssessmentStats(e.stats) >= e.budget {
		e.state = VisionBridgeProbeStateCompleted
		return
	}
	if !e.deadline.IsZero() && !now.Before(e.deadline) {
		e.state = VisionBridgeProbeStateCompleted
	}
}

func (e *visionBridgeProbeEpoch) snapshotLocked(now time.Time) VisionBridgeProbeSnapshot {
	remaining := time.Duration(0)
	if e.state == VisionBridgeProbeStateActive && !e.deadline.IsZero() && now.Before(e.deadline) {
		remaining = e.deadline.Sub(now)
	}
	return VisionBridgeProbeSnapshot{
		ScopeKey:            e.scopeKey,
		State:               e.state,
		Verdict:             e.verdict,
		FailedPendingReason: deriveVisionBridgeFailedPendingReason(e.stats),
		Budget:              e.budget,
		Observed:            nativeObservedVisionBridgeAssessmentStats(e.stats),
		StartedAt:           e.started,
		Deadline:            e.deadline,
		Remaining:           remaining,
		Stats:               e.stats,
	}
}

func observeVisionBridgeProbeAssessment(scope string, assessment VisionBridgeAssessment, pendingQuality VisionPendingQuality, pendingClass VisionPendingClass, pendingGap VisionPendingGap, nativeProvisionalObserved VisionNativeProvisionalSemantic, nativeProvisionalObservedSource VisionNativeProvisionalSemanticSource, nativeProvisionalOutcome VisionNativeProvisionalOutcome, nativeProvisionalOutcomeSource VisionNativeProvisionalOutcomeSource, nativeProvisionalTerminalReason VisionNativeProvisionalTerminalReason) {
	epoch := loadVisionBridgeProbeEpoch(scope)
	if epoch == nil {
		return
	}
	epoch.observe(visionBridgeProbeNowFn(), assessment, pendingQuality, pendingClass, pendingGap, nativeProvisionalObserved, nativeProvisionalObservedSource, nativeProvisionalOutcome, nativeProvisionalOutcomeSource, nativeProvisionalTerminalReason)
}

func deriveVisionBridgeProbeVerdict(stats VisionBridgeAssessmentStats) VisionBridgeProbeVerdict {
	failedPendingReason := deriveVisionBridgeFailedPendingReason(stats)
	switch {
	case stats.NativeDetachFailed > 0:
		return VisionBridgeProbeVerdictNativeDetachFailed
	case stats.NativeDivergent > 0:
		return VisionBridgeProbeVerdictNativeDivergent
	case stats.NativeProvisionalFailedPendingLocalClose > 0 && failedPendingReason == VisionNativeProvisionalTerminalReasonLocalClose:
		return VisionBridgeProbeVerdictNativeProvisionalFailedPendingLocalClose
	case stats.NativeProvisionalFailedPending > 0:
		return VisionBridgeProbeVerdictNativeProvisionalFailedPending
	case stats.NativeProvisionalCommand0BidirectionalFailure > 0:
		return VisionBridgeProbeVerdictNativeProvisionalCommand0Bidirectional
	case stats.NativePendingCommand0BidirectionalFailure > 0:
		return VisionBridgeProbeVerdictNativePendingCommand0Bidirectional
	case stats.NativePendingCommand0Failure > 0:
		return VisionBridgeProbeVerdictNativePendingCommand0
	case stats.NativePendingFailure > 0:
		return VisionBridgeProbeVerdictNativePendingFailure
	case stats.NativeAligned > 0:
		return VisionBridgeProbeVerdictNativeAligned
	case stats.NativePendingBenign > 0:
		return VisionBridgeProbeVerdictNativePendingBenign
	case stats.GoBaseline > 0:
		return VisionBridgeProbeVerdictGoBaseline
	default:
		return VisionBridgeProbeVerdictNoSignal
	}
}

func deriveVisionBridgeFailedPendingReason(stats VisionBridgeAssessmentStats) VisionNativeProvisionalTerminalReason {
	type terminalCount struct {
		reason VisionNativeProvisionalTerminalReason
		count  uint64
	}
	candidates := []terminalCount{
		{VisionNativeProvisionalTerminalReasonReset, stats.NativeProvisionalFailedPendingReset},
		{VisionNativeProvisionalTerminalReasonBrokenPipe, stats.NativeProvisionalFailedPendingBrokenPipe},
		{VisionNativeProvisionalTerminalReasonBadMessage, stats.NativeProvisionalFailedPendingBadMessage},
		{VisionNativeProvisionalTerminalReasonEIO, stats.NativeProvisionalFailedPendingEIO},
		{VisionNativeProvisionalTerminalReasonLocalClose, stats.NativeProvisionalFailedPendingLocalClose},
		{VisionNativeProvisionalTerminalReasonEOF, stats.NativeProvisionalFailedPendingEOF},
		{VisionNativeProvisionalTerminalReasonClosed, stats.NativeProvisionalFailedPendingClosed},
		{VisionNativeProvisionalTerminalReasonOther, stats.NativeProvisionalFailedPendingOther},
	}
	best := VisionNativeProvisionalTerminalReasonNone
	var bestCount uint64
	bestRank := -1
	for _, candidate := range candidates {
		if candidate.count == 0 {
			continue
		}
		rank := visionNativeProvisionalTerminalReasonRank(candidate.reason)
		if candidate.count > bestCount || (candidate.count == bestCount && rank > bestRank) {
			best = candidate.reason
			bestCount = candidate.count
			bestRank = rank
		}
	}
	return best
}

func nativeObservedVisionBridgeAssessmentStats(stats VisionBridgeAssessmentStats) uint64 {
	return stats.NativePending + stats.NativeAligned + stats.NativeDivergent + stats.NativeDetachFailed
}

func alignedVisionBridgeAssessmentBucket(now time.Time) int64 {
	width := visionBridgeAssessmentBucketWidth.Nanoseconds()
	if width <= 0 {
		width = time.Minute.Nanoseconds()
	}
	return (now.UnixNano() / width) * width
}

func shiftVisionBridgeAssessmentBuckets(buckets []uint64, shift int) {
	if shift <= 0 {
		return
	}
	if shift >= len(buckets) {
		clear(buckets)
		return
	}
	copy(buckets, buckets[shift:])
	clear(buckets[len(buckets)-shift:])
}

func sumVisionBridgeAssessmentBuckets(buckets []uint64) uint64 {
	var total uint64
	for _, count := range buckets {
		total += count
	}
	return total
}

func addVisionBridgeAssessmentStats(dst, src VisionBridgeAssessmentStats) VisionBridgeAssessmentStats {
	dst.GoBaseline += src.GoBaseline
	dst.NativePending += src.NativePending
	dst.NativePendingBenign += src.NativePendingBenign
	dst.NativePendingFailure += src.NativePendingFailure
	dst.NativeProvisionalCommand0Bidirectional += src.NativeProvisionalCommand0Bidirectional
	dst.NativeProvisionalCommand0BidirectionalFailure += src.NativeProvisionalCommand0BidirectionalFailure
	dst.NativeProvisionalActive += src.NativeProvisionalActive
	dst.NativeProvisionalTerminatedPending += src.NativeProvisionalTerminatedPending
	dst.NativeProvisionalResolvedDirect += src.NativeProvisionalResolvedDirect
	dst.NativeProvisionalResolvedNoDetach += src.NativeProvisionalResolvedNoDetach
	dst.NativeProvisionalBenignClose += src.NativeProvisionalBenignClose
	dst.NativeProvisionalFailedPending += src.NativeProvisionalFailedPending
	dst.NativeProvisionalFailedPendingLocalClose += src.NativeProvisionalFailedPendingLocalClose
	dst.NativeProvisionalFailedPendingEOF += src.NativeProvisionalFailedPendingEOF
	dst.NativeProvisionalFailedPendingClosed += src.NativeProvisionalFailedPendingClosed
	dst.NativeProvisionalFailedPendingReset += src.NativeProvisionalFailedPendingReset
	dst.NativeProvisionalFailedPendingBrokenPipe += src.NativeProvisionalFailedPendingBrokenPipe
	dst.NativeProvisionalFailedPendingBadMessage += src.NativeProvisionalFailedPendingBadMessage
	dst.NativeProvisionalFailedPendingEIO += src.NativeProvisionalFailedPendingEIO
	dst.NativeProvisionalFailedPendingOther += src.NativeProvisionalFailedPendingOther
	dst.NativePendingCommand0Failure += src.NativePendingCommand0Failure
	dst.NativePendingCommand0BidirectionalFailure += src.NativePendingCommand0BidirectionalFailure
	dst.NativeAligned += src.NativeAligned
	dst.NativeDivergent += src.NativeDivergent
	dst.NativeDetachFailed += src.NativeDetachFailed
	return dst
}

func normalizeVisionDrainMode(direction string) VisionDrainMode {
	switch direction {
	case "buffered-drain":
		return VisionDrainModeBuffered
	case "deferred-detach":
		return VisionDrainModeDeferred
	default:
		if direction == "" {
			return VisionDrainModeNone
		}
		return VisionDrainMode(direction)
	}
}

func visionTransitionTraceKey(conn gonet.Conn, depth int) (gonet.Conn, bool) {
	if conn == nil || depth > 8 {
		return nil, false
	}
	if sc := stat.TryUnwrapStatsConn(conn); sc != nil && sc != conn {
		if key, ok := visionTransitionTraceKey(sc, depth+1); ok {
			return key, true
		}
	}
	if cc, ok := conn.(*encryption.CommonConn); ok && cc != nil {
		if key, ok := visionTransitionTraceKey(cc.Conn, depth+1); ok {
			return key, true
		}
	}
	if unwrap, ok := conn.(visionNetConnUnwrapper); ok {
		if inner := unwrap.NetConn(); inner != nil && inner != conn {
			if key, ok := visionTransitionTraceKey(inner, depth+1); ok {
				return key, true
			}
		}
	}
	return conn, true
}

func buildVisionTransitionSourceForConn(publicConn gonet.Conn, candidate gonet.Conn) (*VisionTransitionSource, bool, error) {
	switch c := candidate.(type) {
	case *encryption.CommonConn:
		source, err := buildVisionBufferedTransitionSource(publicConn, VisionTransitionKindCommonConn, reflect.TypeOf(c).Elem(), uintptr(unsafe.Pointer(c)))
		return source, true, err
	case *tls.Conn:
		source, err := buildVisionBufferedTransitionSource(publicConn, VisionTransitionKindTLSConn, reflect.TypeOf(c.Conn).Elem(), uintptr(unsafe.Pointer(c.Conn)))
		return source, true, err
	case *tls.UConn:
		source, err := buildVisionBufferedTransitionSource(publicConn, VisionTransitionKindUTLSConn, reflect.TypeOf(c.Conn).Elem(), uintptr(unsafe.Pointer(c.Conn)))
		return source, true, err
	case *reality.Conn:
		source, err := buildVisionBufferedTransitionSource(publicConn, VisionTransitionKindRealityConn, reflect.TypeOf(c.Conn).Elem(), uintptr(unsafe.Pointer(c.Conn)))
		return source, true, err
	case *reality.UConn:
		source, err := buildVisionBufferedTransitionSource(publicConn, VisionTransitionKindRealityUConn, reflect.TypeOf(c.Conn).Elem(), uintptr(unsafe.Pointer(c.Conn)))
		return source, true, err
	case *tls.DeferredRustConn:
		source := NewVisionTransitionSource(publicConn, nil, nil)
		source.kind = VisionTransitionKindDeferredRust
		return source, true, nil
	case *tls.RustConn:
		if ktls := c.KTLSEnabled(); !ktls.TxReady || !ktls.RxReady {
			return nil, true, errors.New("RustConn without full kTLS cannot use XTLS Vision").AtWarning()
		}
		return nil, true, errors.New("Vision is incompatible with kTLS-native RustConn").AtWarning()
	default:
		return nil, false, nil
	}
}

func buildVisionBufferedTransitionSource(publicConn gonet.Conn, kind VisionTransitionKind, t reflect.Type, p uintptr) (*VisionTransitionSource, error) {
	i, iOK := t.FieldByName("input")
	r, rOK := t.FieldByName("rawInput")
	if !iOK || !rOK {
		return nil, errors.New("XTLS Vision internal layout mismatch for ", t.String(), ": missing input/rawInput fields").AtWarning()
	}
	source := NewVisionTransitionSource(
		publicConn,
		(*bytes.Reader)(unsafe.Pointer(p+i.Offset)),
		(*bytes.Buffer)(unsafe.Pointer(p+r.Offset)),
	)
	source.kind = kind
	return source, nil
}
