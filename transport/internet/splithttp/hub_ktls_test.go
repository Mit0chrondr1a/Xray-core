package splithttp

import (
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/pipeline"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestXHTTPKTLSListenerEligible(t *testing.T) {
	basePort := net.Port(443)

	tests := []struct {
		name              string
		port              net.Port
		socketSettings    *internet.SocketConfig
		nativeAvailable   bool
		fullKTLSSupported bool
		want              bool
	}{
		{
			name:              "unix socket port",
			port:              net.Port(0),
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "native unavailable",
			port:              basePort,
			nativeAvailable:   false,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "full ktls unsupported",
			port:              basePort,
			nativeAvailable:   true,
			fullKTLSSupported: false,
			want:              false,
		},
		{
			name:              "proxy protocol enabled",
			port:              basePort,
			socketSettings:    &internet.SocketConfig{AcceptProxyProtocol: true},
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "eligible",
			port:              basePort,
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := xhttpKTLSListenerEligible(tc.port, tc.socketSettings, tc.nativeAvailable, tc.fullKTLSSupported)
			if got != tc.want {
				t.Fatalf("xhttpKTLSListenerEligible() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestXHTTPKREALITYListenerEligible(t *testing.T) {
	basePort := net.Port(443)
	baseReality := &reality.Config{}

	tests := []struct {
		name                      string
		port                      net.Port
		socketSettings            *internet.SocketConfig
		realityConfig             *reality.Config
		nativeAvailable           bool
		fullKTLSSupported         bool
		deferredPromotionDisabled bool
		want                      bool
	}{
		{
			name:              "unix socket port",
			port:              net.Port(0),
			realityConfig:     baseReality,
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "missing reality config",
			port:              basePort,
			realityConfig:     nil,
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "native unavailable",
			port:              basePort,
			realityConfig:     baseReality,
			nativeAvailable:   false,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "full ktls unsupported",
			port:              basePort,
			realityConfig:     baseReality,
			nativeAvailable:   true,
			fullKTLSSupported: false,
			want:              false,
		},
		{
			name:                      "deferred promotion cooldown active",
			port:                      basePort,
			realityConfig:             baseReality,
			nativeAvailable:           true,
			fullKTLSSupported:         true,
			deferredPromotionDisabled: true,
			want:                      false,
		},
		{
			name:              "proxy protocol enabled",
			port:              basePort,
			socketSettings:    &internet.SocketConfig{AcceptProxyProtocol: true},
			realityConfig:     baseReality,
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name: "mldsa65 seed configured",
			port: basePort,
			realityConfig: &reality.Config{
				Mldsa65Seed: make([]byte, 32),
			},
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              false,
		},
		{
			name:              "eligible",
			port:              basePort,
			realityConfig:     baseReality,
			nativeAvailable:   true,
			fullKTLSSupported: true,
			want:              true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := xhttpKREALITYListenerEligible(
				tc.port,
				tc.socketSettings,
				tc.realityConfig,
				tc.nativeAvailable,
				tc.fullKTLSSupported,
				tc.deferredPromotionDisabled,
				pipeline.CapabilitySummary{KTLSSupported: true, SockmapSupported: true, SpliceSupported: true},
			)
			if got != tc.want {
				t.Fatalf("xhttpKREALITYListenerEligible() = %v, want %v", got, tc.want)
			}
		})
	}
}

type xhttpAcceptErrStub struct {
	msg       string
	temporary bool
	timeout   bool
}

func (e xhttpAcceptErrStub) Error() string   { return e.msg }
func (e xhttpAcceptErrStub) Temporary() bool { return e.temporary }
func (e xhttpAcceptErrStub) Timeout() bool   { return e.timeout }

func TestXHTTPAcceptErrorClassifiers(t *testing.T) {
	if !xhttpIsTemporaryAcceptErr(xhttpAcceptErrStub{msg: "temporary", temporary: true}) {
		t.Fatal("expected temporary accept error to be retriable")
	}
	if !xhttpIsTemporaryAcceptErr(xhttpAcceptErrStub{msg: "timeout", timeout: true}) {
		t.Fatal("expected timeout accept error to be retriable")
	}
	if xhttpIsTemporaryAcceptErr(errors.New("permanent accept failure")) {
		t.Fatal("did not expect permanent accept error to be retriable")
	}

	if !xhttpIsClosedListenerErr(io.EOF) {
		t.Fatal("expected io.EOF to be treated as closed listener")
	}
	if !xhttpIsClosedListenerErr(stdnet.ErrClosed) {
		t.Fatal("expected net.ErrClosed to be treated as closed listener")
	}
	if !xhttpIsClosedListenerErr(errors.New("use of closed network connection")) {
		t.Fatal("expected closed network connection string to be treated as closed listener")
	}
	if xhttpIsClosedListenerErr(xhttpAcceptErrStub{msg: "temporary", temporary: true}) {
		t.Fatal("did not expect temporary error to be treated as closed listener")
	}
}

func TestXHTTPIsDeferredRealityPeekTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "peek header receive timeout",
			err:  errors.New("native REALITY deferred: peek header: peek_exact: receive timeout"),
			want: true,
		},
		{
			name: "peek record handshake timeout",
			err:  errors.New("native REALITY deferred: peek record: peek_exact: handshake timeout exceeded"),
			want: true,
		},
		{
			name: "peek short read timeout",
			err:  errors.New("native REALITY deferred: peek record: peek_exact: short read after 5 retries (17/517 bytes)"),
			want: true,
		},
		{
			name: "sentinel timeout wraps",
			err:  fmt.Errorf("%w: simulated", native.ErrRealityDeferredPeekTimeout),
			want: true,
		},
		{
			name: "auth failure should not match",
			err:  errors.New("REALITY auth failed: needs fallback"),
			want: false,
		},
		{
			name: "non-timeout deferred error should not match",
			err:  errors.New("native REALITY deferred: handshake: bad certificate"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xhttpIsDeferredRealityPeekTimeout(tt.err); got != tt.want {
				t.Fatalf("xhttpIsDeferredRealityPeekTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXHTTPListenerApplyBackoff(t *testing.T) {
	origSleep := xhttpListenerSleepFn
	defer func() { xhttpListenerSleepFn = origSleep }()

	tests := []struct {
		name    string
		fails   int
		wantHit bool
		wantDur time.Duration
	}{
		{
			name:    "below threshold no backoff",
			fails:   10,
			wantHit: false,
		},
		{
			name:    "first backoff step",
			fails:   11,
			wantHit: true,
			wantDur: 100 * time.Millisecond,
		},
		{
			name:    "backoff capped at 5 seconds",
			fails:   1000,
			wantHit: true,
			wantDur: 5 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []time.Duration
			xhttpListenerSleepFn = func(d time.Duration) { got = append(got, d) }

			xhttpListenerApplyBackoff(tc.fails)

			if tc.wantHit && len(got) != 1 {
				t.Fatalf("xhttpListenerApplyBackoff() sleep calls = %d, want 1", len(got))
			}
			if !tc.wantHit && len(got) != 0 {
				t.Fatalf("xhttpListenerApplyBackoff() sleep calls = %d, want 0", len(got))
			}
			if tc.wantHit && got[0] != tc.wantDur {
				t.Fatalf("xhttpListenerApplyBackoff() duration = %v, want %v", got[0], tc.wantDur)
			}
		})
	}
}
