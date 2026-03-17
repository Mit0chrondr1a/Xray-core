// Package session provides functions for sessions of incoming requests.
package session // import "github.com/xtls/xray-core/common/session"

import (
	"context"
	"math/rand"
	"sync/atomic"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/signal"
)

// CopyGateState enumerates copy-path eligibility states.
type CopyGateState int32

const (
	CopyGateUnset           CopyGateState = iota // legacy default / unspecified
	CopyGateEligible                             // previously 1: can splice/copy fast path
	CopyGatePendingDetach                        // previously 2: pending protocol detach before splice
	CopyGateForcedUserspace                      // previously 3: forced userspace copy
	CopyGateNotApplicable                        // new: transport makes copy path inapplicable
)

func (s CopyGateState) String() string {
	switch s {
	case CopyGateEligible:
		return "copy_eligible"
	case CopyGatePendingDetach:
		return "copy_pending_detach"
	case CopyGateForcedUserspace:
		return "copy_forced_userspace"
	case CopyGateNotApplicable:
		return "copy_not_applicable"
	default:
		return "copy_unset"
	}
}

// CopyGateReason enumerates why copy path is constrained.
type CopyGateReason int32

const (
	CopyGateReasonUnspecified CopyGateReason = iota
	CopyGateReasonFlowNonVisionPolicy
	CopyGateReasonTransportNonRawSplitConn
	CopyGateReasonTransportUserspace
	CopyGateReasonVisionBypass
	CopyGateReasonVisionNoDetach
	CopyGateReasonDetachTimeout
	CopyGateReasonSecurityGuard
	CopyGateReasonMetadataMissing
)

func (r CopyGateReason) String() string {
	switch r {
	case CopyGateReasonFlowNonVisionPolicy:
		return "flow_nonvision_policy"
	case CopyGateReasonTransportNonRawSplitConn:
		return "transport_nonraw_splitconn"
	case CopyGateReasonTransportUserspace:
		return "transport_userspace"
	case CopyGateReasonVisionBypass:
		return "vision_bypass"
	case CopyGateReasonVisionNoDetach:
		return "vision_no_detach"
	case CopyGateReasonDetachTimeout:
		return "detach_timeout"
	case CopyGateReasonSecurityGuard:
		return "security_guard"
	case CopyGateReasonMetadataMissing:
		return "metadata_missing"
	default:
		return "unspecified"
	}
}

// VisionSemanticPhase records explicit Vision protocol truth that should
// outlive transient local userspace phases.
type VisionSemanticPhase int32

const (
	VisionSemanticPhaseUnset VisionSemanticPhase = iota
	VisionSemanticPhaseNoDetach
	VisionSemanticPhasePostDetach
)

// VisionSignal carries explicit Vision command truth across the flow without
// requiring the copy loop to infer semantics from transport timing.
type VisionSignal struct {
	Command int // 0 = pending/unresolved, 1 = no-detach, 2 = post-detach
}

type VisionTimestamps struct {
	detachUnixNano atomic.Int64
}

func (t *VisionTimestamps) StoreDetach(unixNano int64) {
	if t == nil || unixNano <= 0 {
		return
	}
	t.detachUnixNano.Store(unixNano)
}

func (t *VisionTimestamps) ConsumeDetach() (int64, bool) {
	if t == nil {
		return 0, false
	}
	unixNano := t.detachUnixNano.Swap(0)
	return unixNano, unixNano > 0
}

func (t *VisionTimestamps) Clear() {
	if t == nil {
		return
	}
	t.detachUnixNano.Store(0)
}

func (p VisionSemanticPhase) String() string {
	switch p {
	case VisionSemanticPhaseNoDetach:
		return "vision_no_detach"
	case VisionSemanticPhasePostDetach:
		return "vision_post_detach"
	default:
		return "vision_unset"
	}
}

// NewID generates a new ID. The generated ID is high likely to be unique, but not cryptographically secure.
// The generated ID will never be 0.
func NewID() c.ID {
	for {
		id := c.ID(rand.Uint32())
		if id != 0 {
			return id
		}
	}
}

// ExportIDToError transfers session.ID into an error object, for logging purpose.
// This can be used with error.WriteToLog().
func ExportIDToError(ctx context.Context) errors.ExportOption {
	id := c.IDFromContext(ctx)
	return func(h *errors.ExportOptionHolder) {
		h.SessionID = uint32(id)
	}
}

// Inbound is the metadata of an inbound connection.
type Inbound struct {
	// Source address of the inbound connection.
	Source net.Destination
	// Local address of the inbound connection.
	Local net.Destination
	// Gateway address.
	Gateway net.Destination
	// Tag of the inbound proxy that handles the connection.
	Tag string
	// Name of the inbound proxy that handles the connection.
	Name string
	// User is the user that authenticates for the inbound. May be nil if the protocol allows anonymous traffic.
	User *protocol.MemoryUser
	// VlessRoute is the user-sent VLESS UUID's 7th<<8 | 8th bytes.
	VlessRoute net.Port
	// Used by splice copy. Conn is actually internet.Connection. May be nil.
	Conn net.Conn
	// Used by splice copy. Timer of the inbound buf copier. May be nil.
	Timer *signal.ActivityTimer
	// CanSpliceCopy is a property for this connection (legacy backing store).
	// Values are stored using CopyGateState.
	CanSpliceCopy  int32
	copyGateReason int32
	visionSemantic int32
}

// Outbound is the metadata of an outbound connection.
type Outbound struct {
	// Target address of the outbound connection.
	OriginalTarget net.Destination
	Target         net.Destination
	RouteTarget    net.Destination
	// Gateway address
	Gateway net.Address
	// Tag of the outbound proxy that handles the connection.
	Tag string
	// Name of the outbound proxy that handles the connection.
	Name string
	// Unused. Conn is actually internet.Connection. May be nil. It is currently nil for outbound with proxySettings
	Conn net.Conn
	// CanSpliceCopy is a property for this connection (legacy backing store).
	// Values are stored using CopyGateState.
	CanSpliceCopy  int32
	copyGateReason int32
	visionSemantic int32
}

// CopyGateState returns the typed copy-path gate state.
func (i *Inbound) CopyGateState() CopyGateState {
	if i == nil {
		return CopyGateForcedUserspace
	}
	return CopyGateState(atomic.LoadInt32(&i.CanSpliceCopy))
}

// CopyGateReason returns the most recent typed reason attached to the gate state.
func (i *Inbound) CopyGateReason() CopyGateReason {
	if i == nil {
		return CopyGateReasonUnspecified
	}
	return CopyGateReason(atomic.LoadInt32(&i.copyGateReason))
}

// SetCopyGate sets both gate state and reason in one atomic pair of stores.
func (i *Inbound) SetCopyGate(state CopyGateState, reason CopyGateReason) {
	if i == nil {
		return
	}
	atomic.StoreInt32(&i.CanSpliceCopy, int32(state))
	atomic.StoreInt32(&i.copyGateReason, int32(reason))
}

// SetCopyGateReason updates reason while keeping existing state.
func (i *Inbound) SetCopyGateReason(reason CopyGateReason) {
	if i == nil {
		return
	}
	atomic.StoreInt32(&i.copyGateReason, int32(reason))
}

// GetCanSpliceCopy is a compatibility alias returning the typed gate state.
func (i *Inbound) GetCanSpliceCopy() CopyGateState {
	return i.CopyGateState()
}

// SetCanSpliceCopy is a compatibility alias accepting the typed gate state.
func (i *Inbound) SetCanSpliceCopy(state CopyGateState) {
	i.SetCopyGate(state, CopyGateReasonUnspecified)
}

// VisionSemanticPhase returns the strongest explicit Vision semantic committed
// for this connection so far.
func (i *Inbound) VisionSemanticPhase() VisionSemanticPhase {
	if i == nil {
		return VisionSemanticPhaseUnset
	}
	return VisionSemanticPhase(atomic.LoadInt32(&i.visionSemantic))
}

// PromoteVisionSemanticPhase stores stronger explicit semantic truth without
// allowing later weaker states to downgrade it.
func (i *Inbound) PromoteVisionSemanticPhase(phase VisionSemanticPhase) {
	if i == nil || phase == VisionSemanticPhaseUnset {
		return
	}
	for {
		current := atomic.LoadInt32(&i.visionSemantic)
		if int32(phase) <= current {
			return
		}
		if atomic.CompareAndSwapInt32(&i.visionSemantic, current, int32(phase)) {
			return
		}
	}
}

// CopyGateState returns the typed copy-path gate state.
func (o *Outbound) CopyGateState() CopyGateState {
	if o == nil {
		return CopyGateForcedUserspace
	}
	return CopyGateState(atomic.LoadInt32(&o.CanSpliceCopy))
}

// CopyGateReason returns the most recent typed reason attached to the gate state.
func (o *Outbound) CopyGateReason() CopyGateReason {
	if o == nil {
		return CopyGateReasonUnspecified
	}
	return CopyGateReason(atomic.LoadInt32(&o.copyGateReason))
}

// SetCopyGate sets both gate state and reason in one atomic pair of stores.
func (o *Outbound) SetCopyGate(state CopyGateState, reason CopyGateReason) {
	if o == nil {
		return
	}
	atomic.StoreInt32(&o.CanSpliceCopy, int32(state))
	atomic.StoreInt32(&o.copyGateReason, int32(reason))
}

// SetCopyGateReason updates reason while keeping existing state.
func (o *Outbound) SetCopyGateReason(reason CopyGateReason) {
	if o == nil {
		return
	}
	atomic.StoreInt32(&o.copyGateReason, int32(reason))
}

// GetCanSpliceCopy is a compatibility alias returning the typed gate state.
func (o *Outbound) GetCanSpliceCopy() CopyGateState {
	return o.CopyGateState()
}

// SetCanSpliceCopy is a compatibility alias accepting the typed gate state.
func (o *Outbound) SetCanSpliceCopy(state CopyGateState) {
	o.SetCopyGate(state, CopyGateReasonUnspecified)
}

// VisionSemanticPhase returns the strongest explicit Vision semantic committed
// for this connection so far.
func (o *Outbound) VisionSemanticPhase() VisionSemanticPhase {
	if o == nil {
		return VisionSemanticPhaseUnset
	}
	return VisionSemanticPhase(atomic.LoadInt32(&o.visionSemantic))
}

// PromoteVisionSemanticPhase stores stronger explicit semantic truth without
// allowing later weaker states to downgrade it.
func (o *Outbound) PromoteVisionSemanticPhase(phase VisionSemanticPhase) {
	if o == nil || phase == VisionSemanticPhaseUnset {
		return
	}
	for {
		current := atomic.LoadInt32(&o.visionSemantic)
		if int32(phase) <= current {
			return
		}
		if atomic.CompareAndSwapInt32(&o.visionSemantic, current, int32(phase)) {
			return
		}
	}
}

// SniffingRequest controls the behavior of content sniffing. They are from inbound config. Read-only
type SniffingRequest struct {
	ExcludeForDomain               []string
	OverrideDestinationForProtocol []string
	Enabled                        bool
	MetadataOnly                   bool
	RouteOnly                      bool
}

// Content is the metadata of the connection content. Mainly used for routing.
type Content struct {
	// Protocol of current content.
	Protocol string

	SniffingRequest SniffingRequest

	// HTTP traffic sniffed headers
	Attributes map[string]string

	// SkipDNSResolve is set from DNS module. the DOH remote server maybe a domain name, this prevents cycle resolving dead loop
	SkipDNSResolve bool
}

// Sockopt is the settings for socket connection.
type Sockopt struct {
	// Mark of the socket connection.
	Mark int32
}

// SetAttribute attaches additional string attributes to content.
func (c *Content) SetAttribute(name string, value string) {
	if c.Attributes == nil {
		c.Attributes = make(map[string]string)
	}
	c.Attributes[name] = value
}

// Attribute retrieves additional string attributes from content.
func (c *Content) Attribute(name string) string {
	if c.Attributes == nil {
		return ""
	}
	return c.Attributes[name]
}
