package proxy

import (
	"bytes"
	"context"
	gonet "net"
	"os"
	"reflect"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
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
	Kind              VisionTransitionKind
	IngressOrigin     VisionIngressOrigin
	PublicConnType    string
	UsesDeferredRust  bool
	HasBufferedState  bool
	BufferedPlaintext int
	BufferedRawAhead  int
}

type VisionTransitionEvent string

const (
	VisionTransitionEventCommandObserved VisionTransitionEvent = "command_observed"
	VisionTransitionEventPayloadBypass   VisionTransitionEvent = "payload_bypass"
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

var visionIngressOriginByConn sync.Map
var visionTransitionTraceByConn sync.Map

type visionTransitionDirectionTrace struct {
	Command0Count int32
	Command1Count int32
	Command2Count int32
	PayloadBypass bool
}

type visionTransitionTraceSummary struct {
	Kind          VisionTransitionKind
	IngressOrigin VisionIngressOrigin
	Uplink        visionTransitionDirectionTrace
	Downlink      visionTransitionDirectionTrace
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
		Kind:          s.Kind(),
		IngressOrigin: VisionIngressOriginUnknown,
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
	if !debugVisionTransitionTrace() || source == nil {
		return
	}
	snap := source.Snapshot()
	recordVisionTransitionSource(source)
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-source]: ",
		"direction=", direction,
		" transition_kind=", snap.Kind,
		" ingress_origin=", snap.IngressOrigin,
		" public_conn_type=", snap.PublicConnType,
		" uses_deferred_rust=", snap.UsesDeferredRust,
		" has_buffered_state=", snap.HasBufferedState,
		" buffered_plaintext=", snap.BufferedPlaintext,
		" buffered_raw_ahead=", snap.BufferedRawAhead,
	)
}

func LogVisionTransitionDrain(ctx context.Context, direction string, source *VisionTransitionSource, plaintextLen int, rawAheadLen int) {
	if !debugVisionTransitionTrace() || source == nil {
		return
	}
	snap := source.Snapshot()
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-drain]: ",
		"direction=", direction,
		" transition_kind=", snap.Kind,
		" ingress_origin=", snap.IngressOrigin,
		" uses_deferred_rust=", snap.UsesDeferredRust,
		" plaintext_len=", plaintextLen,
		" raw_ahead_len=", rawAheadLen,
	)
}

func LogVisionTransitionEvent(ctx context.Context, direction string, source *VisionTransitionSource, event VisionTransitionEvent, command int, continueCount int32, remainingContent int32, remainingPadding int32, withinPadding bool, switchToDirectCopy bool) {
	if !debugVisionTransitionTrace() || source == nil {
		return
	}
	snap := source.Snapshot()
	recordVisionTransitionEvent(source, direction, event, command)
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-event]: ",
		"direction=", direction,
		" transition_kind=", snap.Kind,
		" ingress_origin=", snap.IngressOrigin,
		" event=", event,
		" command=", command,
		" continue_count=", continueCount,
		" remaining_content=", remainingContent,
		" remaining_padding=", remainingPadding,
		" within_padding=", withinPadding,
		" switch_to_direct_copy=", switchToDirectCopy,
	)
}

func LogVisionTransitionSummary(ctx context.Context, primaryConn gonet.Conn, secondaryConn gonet.Conn) {
	if !debugVisionTransitionTrace() {
		return
	}
	summary, ok := consumeVisionTransitionSummary(primaryConn, secondaryConn)
	if !ok {
		return
	}
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-summary]: ",
		" transition_kind=", summary.Kind,
		" ingress_origin=", summary.IngressOrigin,
		" uplink_command0_count=", summary.Uplink.Command0Count,
		" uplink_command1_count=", summary.Uplink.Command1Count,
		" uplink_command2_count=", summary.Uplink.Command2Count,
		" uplink_payload_bypass=", summary.Uplink.PayloadBypass,
		" downlink_command0_count=", summary.Downlink.Command0Count,
		" downlink_command1_count=", summary.Downlink.Command1Count,
		" downlink_command2_count=", summary.Downlink.Command2Count,
		" downlink_payload_bypass=", summary.Downlink.PayloadBypass,
	)
}

// ObserveVisionIngressOrigin records the ingress implementation that produced
// the connection eventually handed to the Vision seam.
//
// This is an opt-in debug oracle keyed by the connection identity. It is
// consumed once when BuildVisionTransitionSource resolves the seam so trace
// logs can correlate Go/native ingress with the exact pre-detach contract
// Vision observed.
func ObserveVisionIngressOrigin(conn gonet.Conn, origin VisionIngressOrigin) {
	if !debugVisionTransitionTrace() || conn == nil || origin == VisionIngressOriginUnknown {
		return
	}
	visionIngressOriginByConn.Store(conn, origin)
}

// BuildVisionTransitionSource preserves the existing Vision buffer extraction
// behavior while making the seam explicit. Callers remain responsible for any
// policy/version checks that are specific to their direction.
func BuildVisionTransitionSource(publicConn gonet.Conn, innerConn gonet.Conn) (*VisionTransitionSource, error) {
	if publicConn == nil {
		publicConn = innerConn
	}
	if source, handled, err := buildVisionTransitionSourceForConn(publicConn, publicConn); handled {
		if source != nil {
			source.origin = consumeVisionIngressOrigin(publicConn, innerConn)
		}
		return source, err
	}
	if innerConn != nil && innerConn != publicConn {
		if source, handled, err := buildVisionTransitionSourceForConn(publicConn, innerConn); handled {
			if source != nil {
				source.origin = consumeVisionIngressOrigin(publicConn, innerConn)
			}
			return source, err
		}
	}
	return nil, errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
}

func consumeVisionIngressOrigin(publicConn gonet.Conn, innerConn gonet.Conn) VisionIngressOrigin {
	if !debugVisionTransitionTrace() {
		return VisionIngressOriginUnknown
	}
	if origin, ok := consumeVisionIngressOriginForConn(publicConn, 0); ok {
		return origin
	}
	if innerConn != nil && innerConn != publicConn {
		if origin, ok := consumeVisionIngressOriginForConn(innerConn, 0); ok {
			return origin
		}
	}
	return VisionIngressOriginUnknown
}

func recordVisionTransitionSource(source *VisionTransitionSource) {
	if source == nil || source.conn == nil {
		return
	}
	key, ok := visionTransitionTraceKey(source.conn, 0)
	if !ok {
		return
	}
	value, _ := visionTransitionTraceByConn.LoadOrStore(key, &visionTransitionTraceSummary{})
	summary, _ := value.(*visionTransitionTraceSummary)
	if summary == nil {
		return
	}
	if summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque {
		summary.Kind = source.Kind()
	}
	if summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown {
		summary.IngressOrigin = source.origin
	}
}

func recordVisionTransitionEvent(source *VisionTransitionSource, direction string, event VisionTransitionEvent, command int) {
	if source == nil || source.conn == nil {
		return
	}
	key, ok := visionTransitionTraceKey(source.conn, 0)
	if !ok {
		return
	}
	value, _ := visionTransitionTraceByConn.LoadOrStore(key, &visionTransitionTraceSummary{})
	summary, _ := value.(*visionTransitionTraceSummary)
	if summary == nil {
		return
	}
	if summary.Kind == "" || summary.Kind == VisionTransitionKindOpaque {
		summary.Kind = source.Kind()
	}
	if summary.IngressOrigin == "" || summary.IngressOrigin == VisionIngressOriginUnknown {
		summary.IngressOrigin = source.origin
	}
	trace := &summary.Downlink
	if direction == "uplink" {
		trace = &summary.Uplink
	}
	switch event {
	case VisionTransitionEventPayloadBypass:
		trace.PayloadBypass = true
	case VisionTransitionEventCommandObserved:
		switch command {
		case 0:
			trace.Command0Count++
		case 1:
			trace.Command1Count++
		case 2:
			trace.Command2Count++
		}
	}
}

func consumeVisionTransitionSummary(primaryConn gonet.Conn, secondaryConn gonet.Conn) (visionTransitionTraceSummary, bool) {
	var merged visionTransitionTraceSummary
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
	return merged, found
}

func consumeVisionTransitionSummaryForConn(conn gonet.Conn, depth int) (visionTransitionTraceSummary, bool) {
	if key, ok := visionTransitionTraceKey(conn, depth); ok {
		if value, ok := visionTransitionTraceByConn.LoadAndDelete(key); ok {
			if summary, ok := value.(*visionTransitionTraceSummary); ok && summary != nil {
				return *summary, true
			}
		}
	}
	return visionTransitionTraceSummary{}, false
}

func mergeVisionTransitionSummaries(dst visionTransitionTraceSummary, src visionTransitionTraceSummary) visionTransitionTraceSummary {
	if dst.Kind == "" || dst.Kind == VisionTransitionKindOpaque {
		dst.Kind = src.Kind
	}
	if dst.IngressOrigin == "" || dst.IngressOrigin == VisionIngressOriginUnknown {
		dst.IngressOrigin = src.IngressOrigin
	}
	dst.Uplink.Command0Count += src.Uplink.Command0Count
	dst.Uplink.Command1Count += src.Uplink.Command1Count
	dst.Uplink.Command2Count += src.Uplink.Command2Count
	dst.Uplink.PayloadBypass = dst.Uplink.PayloadBypass || src.Uplink.PayloadBypass
	dst.Downlink.Command0Count += src.Downlink.Command0Count
	dst.Downlink.Command1Count += src.Downlink.Command1Count
	dst.Downlink.Command2Count += src.Downlink.Command2Count
	dst.Downlink.PayloadBypass = dst.Downlink.PayloadBypass || src.Downlink.PayloadBypass
	return dst
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

func consumeVisionIngressOriginForConn(conn gonet.Conn, depth int) (VisionIngressOrigin, bool) {
	if conn == nil || depth > 8 {
		return VisionIngressOriginUnknown, false
	}
	if value, ok := visionIngressOriginByConn.LoadAndDelete(conn); ok {
		if origin, ok := value.(VisionIngressOrigin); ok && origin != VisionIngressOriginUnknown {
			return origin, true
		}
	}
	if sc := stat.TryUnwrapStatsConn(conn); sc != nil && sc != conn {
		if origin, ok := consumeVisionIngressOriginForConn(sc, depth+1); ok {
			return origin, true
		}
	}
	if cc, ok := conn.(*encryption.CommonConn); ok && cc != nil {
		if origin, ok := consumeVisionIngressOriginForConn(cc.Conn, depth+1); ok {
			return origin, true
		}
	}
	if unwrap, ok := conn.(visionNetConnUnwrapper); ok {
		if inner := unwrap.NetConn(); inner != nil && inner != conn {
			if origin, ok := consumeVisionIngressOriginForConn(inner, depth+1); ok {
				return origin, true
			}
		}
	}
	return VisionIngressOriginUnknown, false
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
