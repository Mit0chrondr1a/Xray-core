package splithttp

import (
	"errors"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
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
		name              string
		port              net.Port
		socketSettings    *internet.SocketConfig
		realityConfig     *reality.Config
		nativeAvailable   bool
		fullKTLSSupported bool
		want              bool
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

func TestKREALITYProcessConnCooldownFallsBackToGoReality(t *testing.T) {
	origCooldown := deferredKTLSPromotionDisabledFn
	origExtract := xhttpExtractFdFn
	origFallback := xhttpRealityServerFn
	origDeferred := xhttpDoRustRealityDeferredFn
	t.Cleanup(func() {
		deferredKTLSPromotionDisabledFn = origCooldown
		xhttpExtractFdFn = origExtract
		xhttpRealityServerFn = origFallback
		xhttpDoRustRealityDeferredFn = origDeferred
	})

	deferredKTLSPromotionDisabledFn = func(string) bool { return true }
	xhttpExtractFdFn = func(stdnet.Conn) (int, error) {
		t.Fatal("ExtractFd should not be called when deferred kTLS promotion is globally paused")
		return 0, nil
	}
	xhttpDoRustRealityDeferredFn = func(*kREALITYListener, int) (*native.DeferredResult, error) {
		t.Fatal("native deferred handshake should not run when deferred kTLS promotion is globally paused")
		return nil, nil
	}

	client, peer := stdnet.Pipe()
	defer client.Close()
	defer peer.Close()

	fallbackCalled := false
	xhttpRealityServerFn = func(conn stdnet.Conn, _ *goreality.Config) (stdnet.Conn, error) {
		fallbackCalled = true
		if conn != client {
			t.Fatalf("fallback conn mismatch: got %T %v", conn, conn)
		}
		return conn, nil
	}

	l := &kREALITYListener{
		realityConfig:     &goreality.Config{},
		realityXrayConfig: &reality.Config{},
	}

	gotConn, err := l.processConn(client)
	if err != nil {
		t.Fatalf("processConn() error = %v, want nil", err)
	}
	if !fallbackCalled {
		t.Fatal("expected Go REALITY fallback to be used during deferred kTLS cooldown")
	}
	if gotConn != client {
		t.Fatalf("processConn() returned %T, want original raw connection fallback", gotConn)
	}
}

func TestKREALITYProcessConnFDExtractFailureFallsBackToGoReality(t *testing.T) {
	origCooldown := deferredKTLSPromotionDisabledFn
	origExtract := xhttpExtractFdFn
	origFallback := xhttpRealityServerFn
	origDeferred := xhttpDoRustRealityDeferredFn
	t.Cleanup(func() {
		deferredKTLSPromotionDisabledFn = origCooldown
		xhttpExtractFdFn = origExtract
		xhttpRealityServerFn = origFallback
		xhttpDoRustRealityDeferredFn = origDeferred
	})

	deferredKTLSPromotionDisabledFn = func(string) bool { return false }
	xhttpExtractFdFn = func(stdnet.Conn) (int, error) {
		return 0, errors.New("no fd in test")
	}
	xhttpDoRustRealityDeferredFn = func(*kREALITYListener, int) (*native.DeferredResult, error) {
		t.Fatal("native deferred handshake should not run after fd extraction failure")
		return nil, nil
	}

	client, peer := stdnet.Pipe()
	defer client.Close()
	defer peer.Close()

	fallbackCalled := false
	xhttpRealityServerFn = func(conn stdnet.Conn, _ *goreality.Config) (stdnet.Conn, error) {
		fallbackCalled = true
		return conn, nil
	}

	l := &kREALITYListener{
		realityConfig:     &goreality.Config{},
		realityXrayConfig: &reality.Config{},
	}

	gotConn, err := l.processConn(client)
	if err != nil {
		t.Fatalf("processConn() error = %v, want nil", err)
	}
	if !fallbackCalled {
		t.Fatal("expected Go REALITY fallback after fd extraction failure")
	}
	if gotConn != client {
		t.Fatalf("processConn() returned %T, want original raw connection fallback", gotConn)
	}
}

func TestKREALITYProcessConnAuthFailureFallsBackToGoReality(t *testing.T) {
	origCooldown := deferredKTLSPromotionDisabledFn
	origExtract := xhttpExtractFdFn
	origFallback := xhttpRealityServerFn
	origDeferred := xhttpDoRustRealityDeferredFn
	t.Cleanup(func() {
		deferredKTLSPromotionDisabledFn = origCooldown
		xhttpExtractFdFn = origExtract
		xhttpRealityServerFn = origFallback
		xhttpDoRustRealityDeferredFn = origDeferred
	})

	deferredKTLSPromotionDisabledFn = func(string) bool { return false }
	xhttpExtractFdFn = func(stdnet.Conn) (int, error) { return 42, nil }
	xhttpDoRustRealityDeferredFn = func(*kREALITYListener, int) (*native.DeferredResult, error) {
		return nil, native.ErrRealityAuthFailed
	}

	client, peer := stdnet.Pipe()
	defer client.Close()
	defer peer.Close()

	fallbackCalled := false
	xhttpRealityServerFn = func(conn stdnet.Conn, _ *goreality.Config) (stdnet.Conn, error) {
		fallbackCalled = true
		return conn, nil
	}

	l := &kREALITYListener{
		realityConfig:     &goreality.Config{},
		realityXrayConfig: &reality.Config{},
		timeout:           time.Second,
	}

	gotConn, err := l.processConn(client)
	if err != nil {
		t.Fatalf("processConn() error = %v, want nil", err)
	}
	if !fallbackCalled {
		t.Fatal("expected Go REALITY fallback after native auth failure")
	}
	if gotConn != client {
		t.Fatalf("processConn() returned %T, want original raw connection fallback", gotConn)
	}
}

func TestKREALITYProcessConnPeekTimeoutFallsBackToGoReality(t *testing.T) {
	origCooldown := deferredKTLSPromotionDisabledFn
	origExtract := xhttpExtractFdFn
	origFallback := xhttpRealityServerFn
	origDeferred := xhttpDoRustRealityDeferredFn
	t.Cleanup(func() {
		deferredKTLSPromotionDisabledFn = origCooldown
		xhttpExtractFdFn = origExtract
		xhttpRealityServerFn = origFallback
		xhttpDoRustRealityDeferredFn = origDeferred
	})

	deferredKTLSPromotionDisabledFn = func(string) bool { return false }
	xhttpExtractFdFn = func(stdnet.Conn) (int, error) { return 42, nil }
	xhttpDoRustRealityDeferredFn = func(*kREALITYListener, int) (*native.DeferredResult, error) {
		return nil, fmt.Errorf("%w: simulated", native.ErrRealityDeferredPeekTimeout)
	}

	client, peer := stdnet.Pipe()
	defer client.Close()
	defer peer.Close()

	fallbackCalled := false
	xhttpRealityServerFn = func(conn stdnet.Conn, _ *goreality.Config) (stdnet.Conn, error) {
		fallbackCalled = true
		return conn, nil
	}

	l := &kREALITYListener{
		realityConfig:     &goreality.Config{},
		realityXrayConfig: &reality.Config{},
		timeout:           time.Second,
	}

	gotConn, err := l.processConn(client)
	if err != nil {
		t.Fatalf("processConn() error = %v, want nil", err)
	}
	if !fallbackCalled {
		t.Fatal("expected Go REALITY fallback after native peek timeout")
	}
	if gotConn != client {
		t.Fatalf("processConn() returned %T, want original raw connection fallback", gotConn)
	}
}

func TestKREALITYProcessConnFatalDeferredErrorDoesNotFallback(t *testing.T) {
	origCooldown := deferredKTLSPromotionDisabledFn
	origExtract := xhttpExtractFdFn
	origFallback := xhttpRealityServerFn
	origDeferred := xhttpDoRustRealityDeferredFn
	t.Cleanup(func() {
		deferredKTLSPromotionDisabledFn = origCooldown
		xhttpExtractFdFn = origExtract
		xhttpRealityServerFn = origFallback
		xhttpDoRustRealityDeferredFn = origDeferred
	})

	deferredKTLSPromotionDisabledFn = func(string) bool { return false }
	xhttpExtractFdFn = func(stdnet.Conn) (int, error) { return 42, nil }
	xhttpDoRustRealityDeferredFn = func(*kREALITYListener, int) (*native.DeferredResult, error) {
		return nil, errors.New("native deferred handshake blew up")
	}
	xhttpRealityServerFn = func(stdnet.Conn, *goreality.Config) (stdnet.Conn, error) {
		t.Fatal("Go REALITY fallback should not run after fatal native deferred error")
		return nil, nil
	}

	client, peer := stdnet.Pipe()
	defer client.Close()
	defer peer.Close()

	l := &kREALITYListener{
		realityConfig:     &goreality.Config{},
		realityXrayConfig: &reality.Config{},
		timeout:           time.Second,
	}

	gotConn, err := l.processConn(client)
	if err == nil {
		t.Fatal("processConn() error = nil, want fatal native deferred handshake error")
	}
	if gotConn != nil {
		t.Fatalf("processConn() returned %T, want nil on fatal native deferred error", gotConn)
	}
}

func TestXHTTPComposeCapabilitiesSummaryReflectsSpliceProbe(t *testing.T) {
	base := pipeline.CapabilitySummary{
		KTLSSupported:    false,
		SockmapSupported: false,
		SpliceSupported:  false,
	}
	got := xhttpComposeCapabilitiesSummary(base, true, true)

	if !got.KTLSSupported {
		t.Fatal("expected KTLSSupported to be true when probe reports support")
	}
	if !got.SockmapSupported {
		t.Fatal("expected SockmapSupported to be true when probe reports support")
	}
	if got.SpliceSupported {
		t.Fatal("expected SpliceSupported to reflect probe result, not be forced true")
	}
}

func TestXHTTPRecordTerminalDecisionPartition(t *testing.T) {
	reset := func() {
		xhttpDecisionRustKTLS.Store(0)
		xhttpDecisionRustUserspace.Store(0)
		xhttpDecisionGoFallback.Store(0)
		xhttpDecisionDrop.Store(0)
	}

	resetCooldown := func() func() {
		orig := deferredKTLSPromotionDisabledFn
		deferredKTLSPromotionDisabledFn = func(string) bool { return true }
		return func() { deferredKTLSPromotionDisabledFn = orig }
	}

	tests := []struct {
		name          string
		snap          pipeline.DecisionSnapshot
		err           error
		wantRust      uint64
		wantUserspace uint64
		wantFallback  uint64
		wantDrop      uint64
	}{
		{
			name: "ktls success",
			snap: pipeline.DecisionSnapshot{
				Path:   pipeline.PathKTLS,
				Reason: pipeline.ReasonKTLSSuccess,
			},
			wantRust:      1,
			wantUserspace: 0,
			wantFallback:  0,
			wantDrop:      0,
		},
		{
			name: "fallback success",
			snap: pipeline.DecisionSnapshot{
				Path:   pipeline.PathUserspace,
				Reason: pipeline.ReasonFallbackSuccess,
			},
			wantRust:      0,
			wantUserspace: 0,
			wantFallback:  1,
			wantDrop:      0,
		},
		{
			name: "native userspace success",
			snap: pipeline.DecisionSnapshot{
				Path:           pipeline.PathUserspace,
				Reason:         pipeline.ReasonKTLSUnsupported,
				TLSOffloadPath: pipeline.TLSOffloadUserspace,
			},
			wantRust:      0,
			wantUserspace: 1,
			wantFallback:  0,
			wantDrop:      0,
		},
		{
			name: "failed fallback counts as drop only",
			snap: pipeline.DecisionSnapshot{
				Path:   pipeline.PathUserspace,
				Reason: pipeline.ReasonFallbackFailed,
			},
			err:           errors.New("fallback failed"),
			wantRust:      0,
			wantUserspace: 0,
			wantFallback:  0,
			wantDrop:      1,
		},
		{
			name: "non-fallback error is drop",
			snap: pipeline.DecisionSnapshot{
				Path:   pipeline.PathUserspace,
				Reason: pipeline.ReasonRustHandshakeFailed,
			},
			err:           errors.New("handshake failed"),
			wantRust:      0,
			wantUserspace: 0,
			wantFallback:  0,
			wantDrop:      1,
		},
		{
			name: "cooldown",
			snap: pipeline.DecisionSnapshot{
				Path:   pipeline.PathUserspace,
				Reason: pipeline.ReasonKTLSPromotionCooldown,
			},
			wantRust:      0,
			wantUserspace: 1,
			wantFallback:  0,
			wantDrop:      0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reset()
			if tt.name == "cooldown" {
				undo := resetCooldown()
				defer undo()
			}
			xhttpRecordTerminalDecision(tt.snap, tt.err)

			if got := xhttpDecisionRustKTLS.Load(); got != tt.wantRust {
				t.Fatalf("xhttpDecisionRustKTLS = %d, want %d", got, tt.wantRust)
			}
			if got := xhttpDecisionRustUserspace.Load(); got != tt.wantUserspace {
				t.Fatalf("xhttpDecisionRustUserspace = %d, want %d", got, tt.wantUserspace)
			}
			if got := xhttpDecisionGoFallback.Load(); got != tt.wantFallback {
				t.Fatalf("xhttpDecisionGoFallback = %d, want %d", got, tt.wantFallback)
			}
			if got := xhttpDecisionDrop.Load(); got != tt.wantDrop {
				t.Fatalf("xhttpDecisionDrop = %d, want %d", got, tt.wantDrop)
			}
		})
	}
}
