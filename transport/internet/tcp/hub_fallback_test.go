package tcp

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/native"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestIsDeferredRealityPeekTimeout(t *testing.T) {
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
			if got := isDeferredRealityPeekTimeout(tt.err); got != tt.want {
				t.Fatalf("isDeferredRealityPeekTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDeferredRealityPeerAbort(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "rustls short read",
			err:  errors.New("native REALITY deferred: handshake: failed to fill whole buffer"),
			want: true,
		},
		{
			name: "wrapped sentinel",
			err:  fmt.Errorf("%w: simulated", native.ErrRealityDeferredHandshakePeerAbort),
			want: true,
		},
		{
			name: "peek timeout does not match",
			err:  fmt.Errorf("%w: simulated", native.ErrRealityDeferredPeekTimeout),
			want: false,
		},
		{
			name: "generic handshake error",
			err:  errors.New("native REALITY deferred: handshake: bad certificate"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDeferredRealityPeerAbort(tt.err); got != tt.want {
				t.Fatalf("isDeferredRealityPeerAbort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNativeBreakerOpensOnThreshold(t *testing.T) {
	policy := defaultNativePathPolicy()
	policy.Breaker.PeekTimeoutThreshold = 2
	policy.Breaker.CooldownSeconds = 10
	scope := "test-breaker-open-threshold"
	nativePathBreakerByScope.Delete(scope)
	t.Cleanup(func() { nativePathBreakerByScope.Delete(scope) })
	cb := getNativePathBreaker(scope, policy)
	now := time.Now()
	cb.recordOutcome(now, nativeAttemptOutcomePeekTimeout)
	cb.recordOutcome(now.Add(time.Second), nativeAttemptOutcomePeekTimeout)

	skip, state, reason := cb.shouldSkip(now.Add(2 * time.Second))
	if !skip {
		t.Fatal("expected breaker to open after threshold")
	}
	if state != nativeBreakerStateOpen {
		t.Fatalf("breaker state = %s, want %s", state, nativeBreakerStateOpen)
	}
	if reason != nativeSkipReasonBreakerCooldown {
		t.Fatalf("breaker reason = %s, want %s", reason, nativeSkipReasonBreakerCooldown)
	}
}

func TestNativeBreakerAuthFailedDoesNotOpen(t *testing.T) {
	policy := defaultNativePathPolicy()
	policy.Breaker.InternalErrorThreshold = 1
	scope := "test-breaker-auth-failed"
	nativePathBreakerByScope.Delete(scope)
	t.Cleanup(func() { nativePathBreakerByScope.Delete(scope) })
	cb := getNativePathBreaker(scope, policy)
	now := time.Now()

	cb.recordOutcome(now, nativeAttemptOutcomeAuthFailed)
	skip, state, _ := cb.shouldSkip(now.Add(time.Second))
	if skip {
		t.Fatal("auth-failed should not open breaker")
	}
	if state != nativeBreakerStateClosed {
		t.Fatalf("breaker state = %s, want %s", state, nativeBreakerStateClosed)
	}
}

func TestNativeBreakerPeerAbortDoesNotOpen(t *testing.T) {
	policy := defaultNativePathPolicy()
	policy.Breaker.InternalErrorThreshold = 1
	scope := "test-breaker-peer-abort"
	nativePathBreakerByScope.Delete(scope)
	t.Cleanup(func() { nativePathBreakerByScope.Delete(scope) })
	cb := getNativePathBreaker(scope, policy)
	now := time.Now()

	cb.recordOutcome(now, nativeAttemptOutcomePeerAbort)
	skip, state, _ := cb.shouldSkip(now.Add(time.Second))
	if skip {
		t.Fatal("peer-abort should not open breaker")
	}
	if state != nativeBreakerStateClosed {
		t.Fatalf("breaker state = %s, want %s", state, nativeBreakerStateClosed)
	}
}

func TestNativeBreakerHalfOpenProbeAndRecovery(t *testing.T) {
	policy := defaultNativePathPolicy()
	policy.Breaker.InternalErrorThreshold = 1
	policy.Breaker.CooldownSeconds = 1
	policy.Breaker.HalfOpenProbeIntervalSeconds = 1
	scope := "test-breaker-half-open-recovery"
	nativePathBreakerByScope.Delete(scope)
	t.Cleanup(func() { nativePathBreakerByScope.Delete(scope) })
	cb := getNativePathBreaker(scope, policy)
	now := time.Now()

	cb.recordOutcome(now, nativeAttemptOutcomeInternalFail)
	if skip, state, _ := cb.shouldSkip(now.Add(100 * time.Millisecond)); !skip || state != nativeBreakerStateOpen {
		t.Fatalf("expected open breaker, got skip=%v state=%s", skip, state)
	}

	afterCooldown := now.Add(1500 * time.Millisecond)
	if skip, state, _ := cb.shouldSkip(afterCooldown); skip || state != nativeBreakerStateHalfOpen {
		t.Fatalf("expected half-open probe window, got skip=%v state=%s", skip, state)
	}

	cb.recordOutcome(afterCooldown.Add(100*time.Millisecond), nativeAttemptOutcomeSuccess)
	if skip, state, _ := cb.shouldSkip(afterCooldown.Add(200 * time.Millisecond)); skip || state != nativeBreakerStateClosed {
		t.Fatalf("expected breaker to close after successful probe, got skip=%v state=%s", skip, state)
	}
}

func TestShouldAttemptNativeRealityDisabledByPolicy(t *testing.T) {
	v := &Listener{
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_DISABLE_NATIVE,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
	}
	decision := shouldAttemptNativeReality(v)
	if decision.Attempt {
		t.Fatal("expected attempt=false when policy mode disables native path")
	}
	if !decision.SkipByPolicy {
		t.Fatal("expected SkipByPolicy=true when policy mode disables native path")
	}
	if decision.SkipReason != nativeSkipReasonPolicyModeDisabled {
		t.Fatalf("skip reason = %s, want %s", decision.SkipReason, nativeSkipReasonPolicyModeDisabled)
	}
}

func TestShouldAttemptNativeRealityDisabledByDebugEnv(t *testing.T) {
	t.Setenv("XRAY_DEBUG_DISABLE_NATIVE_REALITY", "1")

	v := &Listener{
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_AUTO,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
	}
	decision := shouldAttemptNativeReality(v)
	if decision.Attempt {
		t.Fatal("expected attempt=false when debug env disables native path")
	}
	if !decision.SkipByPolicy {
		t.Fatal("expected SkipByPolicy=true when debug env disables native path")
	}
	if decision.SkipReason != nativeSkipReasonDebugDisabled {
		t.Fatalf("skip reason = %s, want %s", decision.SkipReason, nativeSkipReasonDebugDisabled)
	}
}

func TestShouldAttemptNativeRealitySkipByBreaker(t *testing.T) {
	oldUseNative := useNativeRealityServerFn
	useNativeRealityServerFn = func(*Listener) bool { return true }
	defer func() { useNativeRealityServerFn = oldUseNative }()
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	defer func() {
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	}()

	v := &Listener{
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_AUTO,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker: &xrayreality.NativePathBreaker{
					Enabled:                      true,
					PeekTimeoutThreshold:         3,
					InternalErrorThreshold:       1,
					WindowSeconds:                60,
					CooldownSeconds:              30,
					HalfOpenProbeIntervalSeconds: 2,
				},
			},
		},
	}
	scope := nativePathBreakerScopeKey(v)
	nativePathBreakerByScope.Delete(scope)
	t.Cleanup(func() { nativePathBreakerByScope.Delete(scope) })

	first := shouldAttemptNativeReality(v)
	if !first.Attempt {
		t.Fatal("expected initial native attempt to be allowed")
	}
	if first.Breaker == nil {
		t.Fatal("expected breaker instance on allowed attempt")
	}
	first.Breaker.recordOutcome(time.Now(), nativeAttemptOutcomeInternalFail)

	second := shouldAttemptNativeReality(v)
	if !second.SkipByBreaker {
		t.Fatal("expected native attempt to be skipped by open breaker")
	}
	if second.SkipReason != nativeSkipReasonBreakerCooldown {
		t.Fatalf("skip reason = %s, want %s", second.SkipReason, nativeSkipReasonBreakerCooldown)
	}
}

func TestNativePathScopeKeyUsesSemanticIdentity(t *testing.T) {
	v := &Listener{
		inboundTag: "inbound-vision",
	}
	if got := nativePathScopeKey(v); got != "inbound-vision|reality|tcp" {
		t.Fatalf("scope=%s, want inbound-vision|reality|tcp", got)
	}
	v.listener = &net.TCPListener{} // address/port should not affect scope
	if got := nativePathScopeKey(v); got != "inbound-vision|reality|tcp" {
		t.Fatalf("scope changed after listener set: %s", got)
	}
}

func TestForceNativeFailStopOnIneligible(t *testing.T) {
	oldUseNative := useNativeRealityServerFn
	useNativeRealityServerFn = func(*Listener) bool { return false }
	defer func() { useNativeRealityServerFn = oldUseNative }()

	v := &Listener{
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_FORCE_NATIVE,
				AllowFallback:    true, // should be ignored for force mode
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
	}
	decision := shouldAttemptNativeReality(v)
	if !decision.SkipByPolicy {
		t.Fatal("expected skip by policy when native path ineligible")
	}
	if !decision.FailStop {
		t.Fatal("expected fail-stop for FORCE_NATIVE ineligible path")
	}
	if decision.AllowFallback {
		t.Fatal("AllowFallback must be false for FORCE_NATIVE")
	}
}

func TestNativePathScopeKeyDeterministicForUntagged(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	v := &Listener{
		realityXrayConfig: &xrayreality.Config{
			PrivateKey: key,
		},
	}
	first := nativePathScopeKey(v)
	second := nativePathScopeKey(v)
	if first != second {
		t.Fatalf("scope key should be deterministic; got %s vs %s", first, second)
	}
	if first == "untagged|reality|tcp" || first == "" {
		t.Fatalf("scope key must derive from config when untagged; got %s", first)
	}
}

func TestAllowFallbackFalsePreAttemptFailStop(t *testing.T) {
	oldUseNative := useNativeRealityServerFn
	useNativeRealityServerFn = func(*Listener) bool { return false }
	defer func() { useNativeRealityServerFn = oldUseNative }()

	v := &Listener{
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_AUTO,
				AllowFallback:    false,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
	}
	decision := shouldAttemptNativeReality(v)
	if !decision.SkipByPolicy {
		t.Fatal("expected skip by policy when native path ineligible")
	}
	if !decision.FailStop {
		t.Fatal("allowFallback=false should enforce fail-stop pre-attempt")
	}
	if decision.AllowFallback {
		t.Fatal("AllowFallback must be false when policy sets allowFallback=false")
	}
}

func TestForceNativeStripsFallbackEvenWhenEligible(t *testing.T) {
	oldUseNative := useNativeRealityServerFn
	useNativeRealityServerFn = func(*Listener) bool { return true }
	defer func() { useNativeRealityServerFn = oldUseNative }()
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	defer func() {
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	}()

	v := &Listener{
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_FORCE_NATIVE,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
	}
	decision := shouldAttemptNativeReality(v)
	if !decision.Attempt {
		t.Fatal("force native should attempt when eligible")
	}
	if decision.AllowFallback {
		t.Fatal("force native must disable fallback even if config allowed it")
	}
	if !decision.FailStop {
		t.Fatal("force native should mark fail-stop behavior")
	}
}

func TestFinalizeTerminalDecision(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		enforce bool
		want    string
	}{
		{"preserve_native_success", "native_success", true, "native_success"},
		{"preserve_skip_policy", "native_skipped_by_policy", false, "native_skipped_by_policy"},
		{"fallback_to_failstop_when_enforced", "", true, "native_failstop"},
		{"fallback_to_failed_with_fallback_when_not_enforced", "", false, "native_failed_with_fallback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := finalizeTerminalDecision(nativeAttemptDecision{TelemetryEnforce: tt.enforce}, tt.in)
			if got != tt.want {
				t.Fatalf("finalizeTerminalDecision(%q, enforce=%v)=%q, want %q", tt.in, tt.enforce, got, tt.want)
			}
		})
	}
}

func TestLoopbackListenerAutoSkipsNative(t *testing.T) {
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	defer func() {
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	v := &Listener{
		listener:   ln,
		inboundTag: "loopback-test",
		config:     &Config{},
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_AUTO,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
	}
	decision := shouldAttemptNativeReality(v)
	if decision.Attempt {
		t.Fatal("loopback listener in AUTO should skip native path")
	}
	if !decision.SkipByPolicy {
		t.Fatal("expected loopback listener in AUTO to skip by policy")
	}
	if decision.SkipReason != nativeSkipReasonLoopbackAutoGuard {
		t.Fatalf("skip reason = %s, want %s", decision.SkipReason, nativeSkipReasonLoopbackAutoGuard)
	}
}

func TestLoopbackListenerPreferNativeStillAttempts(t *testing.T) {
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	defer func() {
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	v := &Listener{
		listener:   ln,
		inboundTag: "loopback-prefer-native",
		config:     &Config{},
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_PREFER_NATIVE,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
	}
	decision := shouldAttemptNativeReality(v)
	if !decision.Attempt {
		t.Fatal("loopback listener should still attempt native path when policy explicitly prefers native")
	}
	if decision.SkipByPolicy {
		t.Fatalf("unexpected skip by policy: %s", decision.SkipReason)
	}
}

func TestLoopbackConnLocalAddrAutoSkipsNative(t *testing.T) {
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	defer func() {
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	}()
	v := &Listener{
		inboundTag: "loopback-localaddr-auto",
		config:     &Config{},
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_AUTO,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
	}
	decision := shouldAttemptNativeRealityForAddr(v, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9100})
	if decision.Attempt {
		t.Fatal("loopback conn local addr in AUTO should skip native path")
	}
	if !decision.SkipByPolicy {
		t.Fatal("expected loopback conn local addr in AUTO to skip by policy")
	}
	if decision.SkipReason != nativeSkipReasonLoopbackAutoGuard {
		t.Fatalf("skip reason = %s, want %s", decision.SkipReason, nativeSkipReasonLoopbackAutoGuard)
	}
}

func TestLoopbackIngressPreferNativeAttemptsRustThenFallsBack(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	oldUseNative := useNativeRealityServerFn
	oldDoRust := doRustRealityDeferredFn
	oldFallback := realityServerFn
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	useNativeRealityServerFn = nativeRealityServerEligible
	doRustRealityDeferredFn = func(*Listener, int) (*native.DeferredResult, error) {
		return nil, fmt.Errorf("simulated auth fallback: %w", native.ErrRealityAuthFailed)
	}
	realityServerFn = func(conn net.Conn, _ *goreality.Config) (net.Conn, error) {
		return conn, nil
	}
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	defer func() {
		useNativeRealityServerFn = oldUseNative
		doRustRealityDeferredFn = oldDoRust
		realityServerFn = oldFallback
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	}()

	accepted := make(chan struct{}, 1)
	v := &Listener{
		listener:      ln,
		connSemaphore: make(chan struct{}, 8),
		inboundTag:    "loopback-ac2-single",
		realityConfig: &goreality.Config{},
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_PREFER_NATIVE,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
		addConn: func(conn stat.Connection) {
			_ = conn.Close()
			select {
			case accepted <- struct{}{}:
			default:
			}
		},
	}
	scope := nativePathBreakerScopeKey(v)
	nativePathBreakerByScope.Delete(scope)
	defer nativePathBreakerByScope.Delete(scope)

	beforeAttempt := tcpRealityMarkerRustAttempt.Load()
	beforeFallback := tcpRealityMarkerGoFallbackAttempt.Load()
	go v.keepAccepting()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accepted fallback connection")
	}

	if delta := tcpRealityMarkerRustAttempt.Load() - beforeAttempt; delta < 1 {
		t.Fatalf("rust_attempt delta=%d, want >=1 under loopback PREFER_NATIVE native attempt", delta)
	}
	if delta := tcpRealityMarkerGoFallbackAttempt.Load() - beforeFallback; delta < 1 {
		t.Fatalf("go_fallback_attempt delta=%d, want >=1", delta)
	}
}

func TestLoopbackIngressBurstPreferNativeAttemptsRustWithoutStall(t *testing.T) {
	const connections = 24

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	oldUseNative := useNativeRealityServerFn
	oldDoRust := doRustRealityDeferredFn
	oldFallback := realityServerFn
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	useNativeRealityServerFn = nativeRealityServerEligible
	doRustRealityDeferredFn = func(*Listener, int) (*native.DeferredResult, error) {
		return nil, fmt.Errorf("simulated auth fallback: %w", native.ErrRealityAuthFailed)
	}
	realityServerFn = func(conn net.Conn, _ *goreality.Config) (net.Conn, error) {
		return conn, nil
	}
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	defer func() {
		useNativeRealityServerFn = oldUseNative
		doRustRealityDeferredFn = oldDoRust
		realityServerFn = oldFallback
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	}()

	accepted := make(chan struct{}, connections)
	v := &Listener{
		listener:      ln,
		connSemaphore: make(chan struct{}, 64),
		inboundTag:    "loopback-ac5-burst",
		realityConfig: &goreality.Config{},
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_PREFER_NATIVE,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker:          defaultNativePathPolicy().Breaker,
			},
		},
		addConn: func(conn stat.Connection) {
			_ = conn.Close()
			select {
			case accepted <- struct{}{}:
			default:
			}
		},
	}
	scope := nativePathBreakerScopeKey(v)
	nativePathBreakerByScope.Delete(scope)
	defer nativePathBreakerByScope.Delete(scope)

	beforeAttempt := tcpRealityMarkerRustAttempt.Load()
	go v.keepAccepting()

	clients := make([]net.Conn, 0, connections)
	for i := 0; i < connections; i++ {
		c, dialErr := net.Dial("tcp", ln.Addr().String())
		if dialErr != nil {
			for _, cl := range clients {
				_ = cl.Close()
			}
			t.Fatalf("dial #%d failed: %v", i, dialErr)
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for i := 0; i < connections; i++ {
		select {
		case <-accepted:
		case <-deadline.C:
			t.Fatalf("burst stalled: accepted %d/%d connections before timeout", i, connections)
		}
	}

	if delta := tcpRealityMarkerRustAttempt.Load() - beforeAttempt; delta < uint64(connections) {
		t.Fatalf("rust_attempt delta=%d, want >=%d under loopback PREFER_NATIVE native attempt", delta, connections)
	}
}

func TestLoopbackIngressPeerAbortDoesNotOpenBreakerWhenPreferNative(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	oldUseNative := useNativeRealityServerFn
	oldDoRust := doRustRealityDeferredFn
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	useNativeRealityServerFn = nativeRealityServerEligible
	doRustRealityDeferredFn = func(*Listener, int) (*native.DeferredResult, error) {
		return nil, fmt.Errorf("%w: simulated", native.ErrRealityDeferredHandshakePeerAbort)
	}
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	defer func() {
		useNativeRealityServerFn = oldUseNative
		doRustRealityDeferredFn = oldDoRust
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	}()

	v := &Listener{
		listener:      ln,
		connSemaphore: make(chan struct{}, 8),
		inboundTag:    "loopback-peer-abort",
		realityConfig: &goreality.Config{},
		realityXrayConfig: &xrayreality.Config{
			NativePathPolicy: &xrayreality.NativePathPolicy{
				Mode:             xrayreality.NativePathMode_PREFER_NATIVE,
				AllowFallback:    true,
				TelemetryEnforce: true,
				Breaker: &xrayreality.NativePathBreaker{
					Enabled:                      true,
					PeekTimeoutThreshold:         3,
					InternalErrorThreshold:       1,
					WindowSeconds:                60,
					CooldownSeconds:              30,
					HalfOpenProbeIntervalSeconds: 2,
				},
			},
		},
	}
	unexpectedAdd := make(chan struct{}, 1)
	v.addConn = func(conn stat.Connection) {
		_ = conn.Close()
		select {
		case unexpectedAdd <- struct{}{}:
		default:
		}
	}
	scope := nativePathBreakerScopeKey(v)
	nativePathBreakerByScope.Delete(scope)
	defer nativePathBreakerByScope.Delete(scope)

	beforeHandshakeFailed := tcpRealityMarkerRustHandshakeFailed.Load()
	go v.keepAccepting()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tcpRealityMarkerRustHandshakeFailed.Load()-beforeHandshakeFailed >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if delta := tcpRealityMarkerRustHandshakeFailed.Load() - beforeHandshakeFailed; delta < 1 {
		t.Fatalf("rust_handshake_failed delta=%d, want >=1", delta)
	}
	select {
	case <-unexpectedAdd:
		t.Fatal("peer-abort failstop should not reach addConn")
	default:
	}

	decision := shouldAttemptNativeReality(v)
	if !decision.Attempt {
		t.Fatal("peer-abort should not suppress the next native attempt")
	}
	if decision.SkipByBreaker {
		t.Fatalf("peer-abort should not open breaker, got skip reason %s", decision.SkipReason)
	}
}
