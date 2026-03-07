package tcp

import (
	"crypto/sha256"
	"encoding/hex"
	stdnet "net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
)

const (
	nativeBreakerStateClosed   = "closed"
	nativeBreakerStateOpen     = "open"
	nativeBreakerStateHalfOpen = "half_open"
	nativeBreakerStateDisabled = "disabled"
)

const (
	nativeSkipReasonPolicyModeDisabled      = "policy_mode_disabled"
	nativeSkipReasonNativeUnavailable       = "native_unavailable"
	nativeSkipReasonKTLSSupported           = "ktls_not_supported"
	nativeSkipReasonMissingRealityConfig    = "missing_reality_config"
	nativeSkipReasonProxyProtocolEnabled    = "accept_proxy_protocol_enabled"
	nativeSkipReasonLoopbackAutoGuard       = "loopback_listener_auto_guard"
	nativeSkipReasonDeferredPromotionPaused = "deferred_ktls_promotion_cooldown"
	nativeSkipReasonMldsaConfigured         = "mldsa65_seed_configured"
	nativeSkipReasonUnknown                 = "unknown"
	nativeSkipReasonBreakerCooldown         = "breaker_cooldown_active"
	nativeSkipReasonBreakerHalfOpenProbe    = "breaker_half_open_probe_interval"
	nativeSkipReasonDebugDisabled           = "debug_disable_native_reality"
)

type nativeAttemptOutcome string

const (
	nativeAttemptOutcomeSuccess      nativeAttemptOutcome = "success"
	nativeAttemptOutcomeAuthFailed   nativeAttemptOutcome = "auth_failed"
	nativeAttemptOutcomePeekTimeout  nativeAttemptOutcome = "peek_timeout"
	nativeAttemptOutcomePeerAbort    nativeAttemptOutcome = "peer_abort"
	nativeAttemptOutcomeInternalFail nativeAttemptOutcome = "internal_error"
)

type nativeAttemptDecision struct {
	Attempt          bool
	PolicyMode       string
	AllowFallback    bool
	TelemetryEnforce bool
	BreakerState     string
	SkipReason       string
	SkipByPolicy     bool
	SkipByBreaker    bool
	Breaker          *nativePathCircuitBreaker
	ForceNative      bool
	FailStop         bool
}

type nativeBreakerConfig struct {
	enabled               bool
	peekTimeoutThreshold  uint32
	internalErrThreshold  uint32
	window                time.Duration
	cooldown              time.Duration
	halfOpenProbeInterval time.Duration
}

type nativePathCircuitBreaker struct {
	mu sync.Mutex

	config nativeBreakerConfig

	state string

	windowStart      time.Time
	peekTimeoutCount uint32
	internalErrCount uint32

	openUntil   time.Time
	nextProbeAt time.Time
}

var nativePathBreakerByScope sync.Map // scope key -> *nativePathCircuitBreaker
var untaggedNativeScopeCounter atomic.Uint64
var untaggedNativeScopeByListener sync.Map
var nativeEligibilityAvailableFn = native.Available
var nativeEligibilityFullKTLSSupportedFn = tls.NativeFullKTLSSupported

func defaultNativePathPolicy() *reality.NativePathPolicy {
	return &reality.NativePathPolicy{
		Mode:             reality.NativePathMode_AUTO,
		AllowFallback:    true,
		TelemetryEnforce: true,
		Breaker: &reality.NativePathBreaker{
			Enabled:                      true,
			PeekTimeoutThreshold:         3,
			InternalErrorThreshold:       3,
			WindowSeconds:                60,
			CooldownSeconds:              30,
			HalfOpenProbeIntervalSeconds: 2,
		},
	}
}

func effectiveNativePathPolicy(cfg *reality.Config) *reality.NativePathPolicy {
	base := defaultNativePathPolicy()
	if cfg == nil || cfg.GetNativePathPolicy() == nil {
		return base
	}
	in := cfg.GetNativePathPolicy()
	base.Mode = in.GetMode()
	base.AllowFallback = in.GetAllowFallback()
	base.TelemetryEnforce = in.GetTelemetryEnforce()
	if in.GetBreaker() != nil {
		base.Breaker.Enabled = in.GetBreaker().GetEnabled()
		if in.GetBreaker().GetPeekTimeoutThreshold() > 0 {
			base.Breaker.PeekTimeoutThreshold = in.GetBreaker().GetPeekTimeoutThreshold()
		}
		if in.GetBreaker().GetInternalErrorThreshold() > 0 {
			base.Breaker.InternalErrorThreshold = in.GetBreaker().GetInternalErrorThreshold()
		}
		if in.GetBreaker().GetWindowSeconds() > 0 {
			base.Breaker.WindowSeconds = in.GetBreaker().GetWindowSeconds()
		}
		if in.GetBreaker().GetCooldownSeconds() > 0 {
			base.Breaker.CooldownSeconds = in.GetBreaker().GetCooldownSeconds()
		}
		if in.GetBreaker().GetHalfOpenProbeIntervalSeconds() > 0 {
			base.Breaker.HalfOpenProbeIntervalSeconds = in.GetBreaker().GetHalfOpenProbeIntervalSeconds()
		}
	}
	return base
}

func nativePathModeName(mode reality.NativePathMode) string {
	switch mode {
	case reality.NativePathMode_AUTO:
		return "AUTO"
	case reality.NativePathMode_PREFER_NATIVE:
		return "PREFER_NATIVE"
	case reality.NativePathMode_FORCE_NATIVE:
		return "FORCE_NATIVE"
	case reality.NativePathMode_DISABLE_NATIVE:
		return "DISABLE_NATIVE"
	default:
		return "AUTO"
	}
}

func nativePathIneligibleReason(v *Listener) string {
	eligible, reason := nativePathEligibility(v)
	if eligible {
		return nativeSkipReasonUnknown
	}
	return reason
}

func nativePathScopeKey(v *Listener) string {
	tag := semanticScopeTag(v)
	// semantic identity: inbound_tag | security | transport
	return strings.Join([]string{tag, "reality", "tcp"}, "|")
}

func nativePathBreakerScopeKey(v *Listener) string {
	return nativePathScopeKey(v)
}

func semanticScopeTag(v *Listener) string {
	if v != nil && v.inboundTag != "" {
		return v.inboundTag
	}
	if v != nil && v.realityXrayConfig != nil && len(v.realityXrayConfig.PrivateKey) >= 8 {
		sum := sha256.Sum256(v.realityXrayConfig.PrivateKey)
		return "cfg-" + hex.EncodeToString(sum[:4])
	}
	if v != nil {
		if cached, ok := untaggedNativeScopeByListener.Load(v); ok {
			if s, ok2 := cached.(string); ok2 {
				return s
			}
		}
		id := untaggedNativeScopeCounter.Add(1)
		scope := "untagged-" + strconv.FormatUint(id, 10)
		if actual, _ := untaggedNativeScopeByListener.LoadOrStore(v, scope); actual != nil {
			if s, ok := actual.(string); ok {
				return s
			}
		}
		return scope
	}
	id := untaggedNativeScopeCounter.Add(1)
	return "untagged-" + strconv.FormatUint(id, 10)
}

func nativePathEligibility(v *Listener) (bool, string) {
	return nativePathEligibilityWith(v, nativeEligibilityAvailableFn(), nativeEligibilityFullKTLSSupportedFn())
}

func nativePathEligibilityWith(v *Listener, nativeAvailable, fullKTLS bool) (bool, string) {
	if !nativeAvailable {
		return false, nativeSkipReasonNativeUnavailable
	}
	if !fullKTLS {
		return false, nativeSkipReasonKTLSSupported
	}
	if v == nil || v.realityXrayConfig == nil {
		return false, nativeSkipReasonMissingRealityConfig
	}
	if v.config != nil && v.config.AcceptProxyProtocol {
		return false, nativeSkipReasonProxyProtocolEnabled
	}
	if len(v.realityXrayConfig.Mldsa65Seed) > 0 {
		return false, nativeSkipReasonMldsaConfigured
	}
	return true, ""
}

func nativeBreakerFromPolicy(policy *reality.NativePathPolicy) nativeBreakerConfig {
	b := policy.GetBreaker()
	cfg := nativeBreakerConfig{
		enabled:               b.GetEnabled(),
		peekTimeoutThreshold:  b.GetPeekTimeoutThreshold(),
		internalErrThreshold:  b.GetInternalErrorThreshold(),
		window:                time.Duration(b.GetWindowSeconds()) * time.Second,
		cooldown:              time.Duration(b.GetCooldownSeconds()) * time.Second,
		halfOpenProbeInterval: time.Duration(b.GetHalfOpenProbeIntervalSeconds()) * time.Second,
	}
	if cfg.peekTimeoutThreshold == 0 {
		cfg.peekTimeoutThreshold = 3
	}
	if cfg.internalErrThreshold == 0 {
		cfg.internalErrThreshold = 3
	}
	if cfg.window <= 0 {
		cfg.window = 60 * time.Second
	}
	if cfg.cooldown <= 0 {
		cfg.cooldown = 30 * time.Second
	}
	if cfg.halfOpenProbeInterval <= 0 {
		cfg.halfOpenProbeInterval = 2 * time.Second
	}
	return cfg
}

func getNativePathBreaker(scope string, policy *reality.NativePathPolicy) *nativePathCircuitBreaker {
	cfg := nativeBreakerFromPolicy(policy)
	if existing, ok := nativePathBreakerByScope.Load(scope); ok {
		cb, _ := existing.(*nativePathCircuitBreaker)
		if cb != nil {
			cb.updateConfig(cfg)
			return cb
		}
	}
	cb := &nativePathCircuitBreaker{
		config: cfg,
		state:  nativeBreakerStateClosed,
	}
	actual, _ := nativePathBreakerByScope.LoadOrStore(scope, cb)
	stored, _ := actual.(*nativePathCircuitBreaker)
	if stored != nil {
		stored.updateConfig(cfg)
		return stored
	}
	return cb
}

func (cb *nativePathCircuitBreaker) updateConfig(cfg nativeBreakerConfig) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.config = cfg
	if !cfg.enabled {
		cb.state = nativeBreakerStateClosed
		cb.peekTimeoutCount = 0
		cb.internalErrCount = 0
		cb.windowStart = time.Time{}
		cb.openUntil = time.Time{}
		cb.nextProbeAt = time.Time{}
	}
}

func (cb *nativePathCircuitBreaker) shouldSkip(now time.Time) (skip bool, state string, reason string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if !cb.config.enabled {
		return false, nativeBreakerStateDisabled, ""
	}
	if cb.state == "" {
		cb.state = nativeBreakerStateClosed
	}
	switch cb.state {
	case nativeBreakerStateOpen:
		if now.Before(cb.openUntil) {
			return true, nativeBreakerStateOpen, nativeSkipReasonBreakerCooldown
		}
		cb.state = nativeBreakerStateHalfOpen
		cb.nextProbeAt = now
		fallthrough
	case nativeBreakerStateHalfOpen:
		if now.Before(cb.nextProbeAt) {
			return true, nativeBreakerStateHalfOpen, nativeSkipReasonBreakerHalfOpenProbe
		}
		cb.nextProbeAt = now.Add(cb.config.halfOpenProbeInterval)
		return false, nativeBreakerStateHalfOpen, ""
	default:
		return false, nativeBreakerStateClosed, ""
	}
}

func (cb *nativePathCircuitBreaker) recordOutcome(now time.Time, outcome nativeAttemptOutcome) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if !cb.config.enabled {
		return
	}
	if cb.state == "" {
		cb.state = nativeBreakerStateClosed
	}
	if outcome == nativeAttemptOutcomeSuccess {
		cb.state = nativeBreakerStateClosed
		cb.peekTimeoutCount = 0
		cb.internalErrCount = 0
		cb.windowStart = now
		cb.openUntil = time.Time{}
		cb.nextProbeAt = time.Time{}
		return
	}
	if outcome == nativeAttemptOutcomeAuthFailed || outcome == nativeAttemptOutcomePeerAbort {
		return
	}
	if cb.windowStart.IsZero() || now.Sub(cb.windowStart) >= cb.config.window {
		cb.windowStart = now
		cb.peekTimeoutCount = 0
		cb.internalErrCount = 0
	}
	switch outcome {
	case nativeAttemptOutcomePeekTimeout:
		cb.peekTimeoutCount++
	case nativeAttemptOutcomeInternalFail:
		cb.internalErrCount++
	}
	if cb.state == nativeBreakerStateHalfOpen {
		cb.openLocked(now)
		return
	}
	if cb.peekTimeoutCount >= cb.config.peekTimeoutThreshold || cb.internalErrCount >= cb.config.internalErrThreshold {
		cb.openLocked(now)
	}
}

func (cb *nativePathCircuitBreaker) openLocked(now time.Time) {
	cb.state = nativeBreakerStateOpen
	cb.openUntil = now.Add(cb.config.cooldown)
}

func shouldAttemptNativeReality(v *Listener) nativeAttemptDecision {
	var localAddr stdnet.Addr
	if v != nil && v.listener != nil {
		localAddr = v.listener.Addr()
	}
	return shouldAttemptNativeRealityForAddr(v, localAddr)
}

func isLoopbackAddr(addr stdnet.Addr) bool {
	switch a := addr.(type) {
	case *stdnet.TCPAddr:
		return a != nil && a.IP != nil && a.IP.IsLoopback()
	case *stdnet.UDPAddr:
		return a != nil && a.IP != nil && a.IP.IsLoopback()
	default:
		return false
	}
}

func shouldAttemptNativeRealityForAddr(v *Listener, localAddr stdnet.Addr) nativeAttemptDecision {
	policy := effectiveNativePathPolicy(v.realityXrayConfig)
	decision := nativeAttemptDecision{
		PolicyMode:       nativePathModeName(policy.GetMode()),
		AllowFallback:    policy.GetAllowFallback(),
		TelemetryEnforce: policy.GetTelemetryEnforce(),
		BreakerState:     nativeBreakerStateDisabled,
		FailStop:         !policy.GetAllowFallback(),
		ForceNative:      policy.GetMode() == reality.NativePathMode_FORCE_NATIVE,
	}
	if decision.ForceNative {
		decision.AllowFallback = false
		decision.FailStop = true
	}
	if os.Getenv("XRAY_DEBUG_DISABLE_NATIVE_REALITY") == "1" {
		decision.SkipByPolicy = true
		decision.SkipReason = nativeSkipReasonDebugDisabled
		return decision
	}
	if policy.GetMode() == reality.NativePathMode_DISABLE_NATIVE {
		decision.SkipByPolicy = true
		decision.SkipReason = nativeSkipReasonPolicyModeDisabled
		if decision.ForceNative {
			decision.FailStop = true
		}
		return decision
	}
	if ok, reason := nativePathEligibility(v); !ok {
		decision.SkipByPolicy = true
		decision.SkipReason = reason
		if decision.ForceNative {
			decision.FailStop = true
		}
		return decision
	}
	if policy.GetMode() == reality.NativePathMode_AUTO && isLoopbackAddr(localAddr) {
		decision.SkipByPolicy = true
		decision.SkipReason = nativeSkipReasonLoopbackAutoGuard
		return decision
	}
	breaker := getNativePathBreaker(nativePathBreakerScopeKey(v), policy)
	skip, state, reason := breaker.shouldSkip(time.Now())
	decision.Breaker = breaker
	decision.BreakerState = state
	if skip {
		decision.SkipByBreaker = true
		decision.SkipReason = reason
		if decision.ForceNative {
			decision.FailStop = true
		}
		return decision
	}
	switch policy.GetMode() {
	case reality.NativePathMode_AUTO, reality.NativePathMode_PREFER_NATIVE, reality.NativePathMode_FORCE_NATIVE:
		decision.Attempt = true
	default:
		decision.SkipByPolicy = true
		decision.SkipReason = nativeSkipReasonPolicyModeDisabled
	}
	return decision
}
