package proxy

import (
	"bytes"
	"context"
	gonet "net"
	"os"
	"reflect"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/reality"
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

type VisionTransitionSnapshot struct {
	Kind              VisionTransitionKind
	PublicConnType    string
	UsesDeferredRust  bool
	HasBufferedState  bool
	BufferedPlaintext int
	BufferedRawAhead  int
}

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
		Kind: s.Kind(),
	}
	if s == nil {
		return snap
	}
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
	errors.LogInfo(ctx, "proxy markers[kind=vision-transition-source]: ",
		"direction=", direction,
		" transition_kind=", snap.Kind,
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
		" uses_deferred_rust=", snap.UsesDeferredRust,
		" plaintext_len=", plaintextLen,
		" raw_ahead_len=", rawAheadLen,
	)
}

// BuildVisionTransitionSource preserves the existing Vision buffer extraction
// behavior while making the seam explicit. Callers remain responsible for any
// policy/version checks that are specific to their direction.
func BuildVisionTransitionSource(publicConn gonet.Conn, innerConn gonet.Conn) (*VisionTransitionSource, error) {
	if publicConn == nil {
		publicConn = innerConn
	}
	if source, handled, err := buildVisionTransitionSourceForConn(publicConn, publicConn); handled {
		return source, err
	}
	if innerConn != nil && innerConn != publicConn {
		if source, handled, err := buildVisionTransitionSourceForConn(publicConn, innerConn); handled {
			return source, err
		}
	}
	return nil, errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
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
