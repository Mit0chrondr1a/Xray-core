package proxy

import (
	"bytes"
	gonet "net"
	"reflect"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
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
}

func NewVisionTransitionSource(conn gonet.Conn, input *bytes.Reader, rawInput *bytes.Buffer) *VisionTransitionSource {
	return &VisionTransitionSource{
		conn:     conn,
		input:    input,
		rawInput: rawInput,
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
		source, err := buildVisionBufferedTransitionSource(publicConn, reflect.TypeOf(c).Elem(), uintptr(unsafe.Pointer(c)))
		return source, true, err
	case *tls.Conn:
		source, err := buildVisionBufferedTransitionSource(publicConn, reflect.TypeOf(c.Conn).Elem(), uintptr(unsafe.Pointer(c.Conn)))
		return source, true, err
	case *tls.UConn:
		source, err := buildVisionBufferedTransitionSource(publicConn, reflect.TypeOf(c.Conn).Elem(), uintptr(unsafe.Pointer(c.Conn)))
		return source, true, err
	case *reality.Conn:
		source, err := buildVisionBufferedTransitionSource(publicConn, reflect.TypeOf(c.Conn).Elem(), uintptr(unsafe.Pointer(c.Conn)))
		return source, true, err
	case *reality.UConn:
		source, err := buildVisionBufferedTransitionSource(publicConn, reflect.TypeOf(c.Conn).Elem(), uintptr(unsafe.Pointer(c.Conn)))
		return source, true, err
	case *tls.DeferredRustConn:
		return NewVisionTransitionSource(publicConn, nil, nil), true, nil
	case *tls.RustConn:
		if ktls := c.KTLSEnabled(); !ktls.TxReady || !ktls.RxReady {
			return nil, true, errors.New("RustConn without full kTLS cannot use XTLS Vision").AtWarning()
		}
		return nil, true, errors.New("Vision is incompatible with kTLS-native RustConn").AtWarning()
	default:
		return nil, false, nil
	}
}

func buildVisionBufferedTransitionSource(publicConn gonet.Conn, t reflect.Type, p uintptr) (*VisionTransitionSource, error) {
	i, iOK := t.FieldByName("input")
	r, rOK := t.FieldByName("rawInput")
	if !iOK || !rOK {
		return nil, errors.New("XTLS Vision internal layout mismatch for ", t.String(), ": missing input/rawInput fields").AtWarning()
	}
	return NewVisionTransitionSource(
		publicConn,
		(*bytes.Reader)(unsafe.Pointer(p+i.Offset)),
		(*bytes.Buffer)(unsafe.Pointer(p+r.Offset)),
	), nil
}
