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

type VisionTransitionDirectionSummary struct {
	Command0Count int32
	Command1Count int32
	Command2Count int32
	PayloadBypass bool
	Semantic      VisionSemantic
}

type VisionTransitionSummary struct {
	Kind                VisionTransitionKind
	IngressOrigin       VisionIngressOrigin
	Uplink              VisionTransitionDirectionSummary
	Downlink            VisionTransitionDirectionSummary
	DrainMode           VisionDrainMode
	DrainCount          int32
	DrainPlaintextBytes int
	DrainRawAheadBytes  int
}

func newVisionTransitionSummary() *VisionTransitionSummary {
	return &VisionTransitionSummary{
		Uplink: VisionTransitionDirectionSummary{
			Semantic: VisionSemanticUnknown,
		},
		Downlink: VisionTransitionDirectionSummary{
			Semantic: VisionSemanticUnknown,
		},
		DrainMode: VisionDrainModeNone,
	}
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
	ObserveVisionTransitionDrain(source.conn, source.Kind(), source.origin, normalizeVisionDrainMode(direction), plaintextLen, rawAheadLen)
	if !debugVisionTransitionTrace() {
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
	summary, ok := consumeVisionTransitionSummary(primaryConn, secondaryConn)
	if !ok {
		return
	}
	if !debugVisionTransitionTrace() {
		return
	}
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-summary]: ",
		" transition_kind=", summary.Kind,
		" ingress_origin=", summary.IngressOrigin,
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
		" drain_mode=", summary.DrainMode,
		" drain_count=", summary.DrainCount,
		" drain_plaintext_bytes=", summary.DrainPlaintextBytes,
		" drain_raw_ahead_bytes=", summary.DrainRawAheadBytes,
	)
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
	return merged, found
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
	return merged, found
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
	dst.DrainMode = mergeVisionDrainMode(dst.DrainMode, src.DrainMode)
	dst.DrainCount += src.DrainCount
	dst.DrainPlaintextBytes += src.DrainPlaintextBytes
	dst.DrainRawAheadBytes += src.DrainRawAheadBytes
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
