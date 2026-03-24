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

const (
	nativeRealityModeEnv = "XRAY_DEBUG_NATIVE_REALITY_MODE"
)

type nativeAttemptOutcome string

const (
	nativeAttemptOutcomeSuccess      nativeAttemptOutcome = "success"
	nativeAttemptOutcomeAuthFailed   nativeAttemptOutcome = "auth_failed"
	nativeAttemptOutcomePeekTimeout  nativeAttemptOutcome = "peek_timeout"
	nativeAttemptOutcomePeerAbort    nativeAttemptOutcome = "peer_abort"
	nativeAttemptOutcomeInternalFail nativeAttemptOutcome = "internal_error"
	nativeAttemptOutcomeRuntimeFail  nativeAttemptOutcome = "runtime_regression"
	nativeAttemptOutcomeRuntimeOK    nativeAttemptOutcome = "runtime_recovery"
)

type nativeAttemptDecision struct {
	Attempt          bool
	PolicyMode       string
	AllowFallback    bool
	TelemetryEnforce bool
	BreakerState     string
	BreakerCause     string
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
	runtimeErrThreshold   uint32
	window                time.Duration
	cooldown              time.Duration
	halfOpenProbeInterval time.Duration
}

type nativePathCircuitBreaker struct {
	mu sync.Mutex

	config nativeBreakerConfig

	state string
	cause nativeAttemptOutcome

	windowStart        time.Time
	runtimeWindowStart time.Time
	lastOutcomeAt      time.Time
	lastRuntimeFailAt  time.Time
	peekTimeoutCount   uint32
	internalErrCount   uint32
	runtimeErrCount    uint32
	runtimeOpenStreak  uint32
	runtimeOKCount     uint32

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
		if override, ok := debugNativePathModeOverride(); ok {
			base.Mode = override
		}
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
	if override, ok := debugNativePathModeOverride(); ok {
		base.Mode = override
	}
	return base
}

func debugNativePathModeOverride() (reality.NativePathMode, bool) {
	raw := strings.TrimSpace(os.Getenv(nativeRealityModeEnv))
	if raw == "" {
		return reality.NativePathMode_AUTO, false
	}
	normalized := strings.ToUpper(strings.ReplaceAll(raw, "-", "_"))
	switch normalized {
	case "AUTO":
		return reality.NativePathMode_AUTO, true
	case "PREFER_NATIVE", "PREFER":
		return reality.NativePathMode_PREFER_NATIVE, true
	case "FORCE_NATIVE", "FORCE":
		return reality.NativePathMode_FORCE_NATIVE, true
	case "DISABLE_NATIVE", "DISABLE", "OFF":
		return reality.NativePathMode_DISABLE_NATIVE, true
	default:
		return reality.NativePathMode_AUTO, false
	}
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
	return nativePathScopeKeyForTag(tag)
}

func nativePathBreakerScopeKey(v *Listener) string {
	return nativePathScopeKey(v)
}

func nativePathScopeKeyForTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ""
	}
	return strings.Join([]string{tag, "reality", "tcp"}, "|")
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
	cfg.runtimeErrThreshold = runtimeRegressionThresholdFor(cfg.internalErrThreshold)
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
		cb.cause = ""
		cb.peekTimeoutCount = 0
		cb.internalErrCount = 0
		cb.runtimeErrCount = 0
		cb.runtimeOpenStreak = 0
		cb.windowStart = time.Time{}
		cb.runtimeWindowStart = time.Time{}
		cb.lastOutcomeAt = time.Time{}
		cb.lastRuntimeFailAt = time.Time{}
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
		cb.runtimeOKCount = 0
		cb.nextProbeAt = now
		fallthrough
	case nativeBreakerStateHalfOpen:
		if now.Before(cb.nextProbeAt) {
			return true, nativeBreakerStateHalfOpen, nativeSkipReasonBreakerHalfOpenProbe
		}
		cb.nextProbeAt = now.Add(cb.config.halfOpenProbeInterval)
		return false, nativeBreakerStateHalfOpen, ""
	default:
		if cb.shouldRequireIdleRuntimeProbeLocked(now) {
			cb.state = nativeBreakerStateHalfOpen
			// Keep runtime-regression causality on the cautious re-entry probe so
			// a mere handshake success does not immediately restore fully-open
			// native admission after a quiet period.
			cb.cause = nativeAttemptOutcomeRuntimeFail
			cb.runtimeOKCount = 0
			cb.nextProbeAt = now.Add(cb.config.halfOpenProbeInterval)
			return false, nativeBreakerStateHalfOpen, ""
		}
		return false, nativeBreakerStateClosed, ""
	}
}

func (cb *nativePathCircuitBreaker) snapshotCause() string {
	if cb == nil {
		return ""
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return string(cb.cause)
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
	cb.lastOutcomeAt = now
	if outcome == nativeAttemptOutcomeRuntimeOK {
		if cb.cause == nativeAttemptOutcomeRuntimeFail {
			switch cb.state {
			case nativeBreakerStateOpen:
				// Healthy outcomes arriving from sessions that were already in
				// flight when the breaker opened are useful evidence, but they
				// should not collapse the runtime cooldown immediately while
				// sibling unresolved flows may still be reporting regressions.
				return
			case nativeBreakerStateHalfOpen:
				cb.runtimeOKCount++
				if cb.runtimeOKCount < runtimeRecoveryThresholdFor() {
					cb.nextProbeAt = now.Add(cb.config.halfOpenProbeInterval)
					return
				}
			}
		}
		cb.state = nativeBreakerStateClosed
		cb.cause = ""
		cb.peekTimeoutCount = 0
		cb.internalErrCount = 0
		cb.runtimeErrCount = 0
		cb.runtimeOpenStreak = 0
		cb.runtimeOKCount = 0
		cb.windowStart = now
		cb.runtimeWindowStart = now
		cb.openUntil = time.Time{}
		cb.nextProbeAt = time.Time{}
		return
	}
	if outcome == nativeAttemptOutcomeSuccess {
		if cb.state == nativeBreakerStateHalfOpen && cb.cause == nativeAttemptOutcomeRuntimeFail {
			// Runtime-induced half-open needs proof that the post-admission
			// execution is healthy again, not just a successful handshake.
			return
		}
		cb.state = nativeBreakerStateClosed
		cb.cause = ""
		cb.peekTimeoutCount = 0
		cb.internalErrCount = 0
		// Successful handshakes do not prove post-admission runtime health.
		// Keep runtime regressions pending until explicit runtime recovery or
		// the observation window rolls over.
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
	case nativeAttemptOutcomeRuntimeFail:
		cb.lastRuntimeFailAt = now
		if cb.runtimeWindowStart.IsZero() || now.Sub(cb.runtimeWindowStart) >= cb.config.window {
			cb.runtimeWindowStart = now
			cb.runtimeErrCount = 0
			cb.runtimeOpenStreak = 0
		}
		cb.runtimeErrCount++
	}
	if cb.state == nativeBreakerStateHalfOpen {
		cb.openLocked(now, outcome)
		return
	}
	if cb.peekTimeoutCount >= cb.config.peekTimeoutThreshold ||
		cb.internalErrCount >= cb.config.internalErrThreshold ||
		cb.runtimeErrCount >= cb.config.runtimeErrThreshold {
		cb.openLocked(now, outcome)
	}
}

func runtimeRegressionThresholdFor(internalErrThreshold uint32) uint32 {
	// Runtime regressions are user-visible post-admission compatibility failures.
	// On the shared listener, one confirmed regression is enough to prefer the
	// already-proven Go/fallback path until a robust runtime recovery happens.
	return 1
}

func nativeRuntimeReentryIdleFor(base time.Duration) time.Duration {
	idle := 4 * base
	if idle < 2*time.Minute {
		idle = 2 * time.Minute
	}
	return idle
}

func nativeRuntimeRegressionMemoryFor(base time.Duration) time.Duration {
	window := 20 * base
	if window < 10*time.Minute {
		window = 10 * time.Minute
	}
	return window
}

func runtimeRecoveryThresholdFor() uint32 {
	// A single healthy native session is not enough to reopen the shared
	// listener after runtime regressions because in-flight siblings from the
	// same burst may still be failing. Require multiple serialized half-open
	// runtime successes before returning to fully closed admission.
	return 2
}

// ReportNativeRuntimeRegressionByTag records a post-admission runtime regression
// against the existing native breaker for the semantic inbound scope identified
// by tag. It is intentionally conservative: if the breaker does not already
// exist for that scope, no new breaker is created.
func ReportNativeRuntimeRegressionByTag(tag string) bool {
	scope := nativePathScopeKeyForTag(tag)
	if scope == "" {
		return false
	}
	existing, ok := nativePathBreakerByScope.Load(scope)
	if !ok {
		return false
	}
	cb, _ := existing.(*nativePathCircuitBreaker)
	if cb == nil {
		return false
	}
	cb.recordOutcome(time.Now(), nativeAttemptOutcomeRuntimeFail)
	return true
}

// ReportNativeRuntimeRecoveryByTag records a healthy post-admission runtime
// outcome for an existing native breaker scope.
func ReportNativeRuntimeRecoveryByTag(tag string) bool {
	scope := nativePathScopeKeyForTag(tag)
	if scope == "" {
		return false
	}
	existing, ok := nativePathBreakerByScope.Load(scope)
	if !ok {
		return false
	}
	cb, _ := existing.(*nativePathCircuitBreaker)
	if cb == nil {
		return false
	}
	cb.recordOutcome(time.Now(), nativeAttemptOutcomeRuntimeOK)
	return true
}

func (cb *nativePathCircuitBreaker) openLocked(now time.Time, cause nativeAttemptOutcome) {
	cb.state = nativeBreakerStateOpen
	cb.cause = cause
	cb.runtimeOKCount = 0
	cooldown := cb.config.cooldown
	if cause == nativeAttemptOutcomeRuntimeFail {
		cb.runtimeOpenStreak++
		cooldown = nativeRuntimeCooldownFor(cb.config.cooldown, cb.runtimeOpenStreak)
	} else {
		cb.runtimeOpenStreak = 0
	}
	cb.openUntil = now.Add(cooldown)
}

func (cb *nativePathCircuitBreaker) shouldRequireIdleRuntimeProbeLocked(now time.Time) bool {
	if cb == nil || cb.state != nativeBreakerStateClosed {
		return false
	}
	if cb.lastOutcomeAt.IsZero() || cb.lastRuntimeFailAt.IsZero() {
		return false
	}
	if now.Sub(cb.lastRuntimeFailAt) >= nativeRuntimeRegressionMemoryFor(cb.config.cooldown) {
		return false
	}
	return now.Sub(cb.lastOutcomeAt) >= nativeRuntimeReentryIdleFor(cb.config.cooldown)
}

func nativeRuntimeCooldownFor(base time.Duration, streak uint32) time.Duration {
	if base <= 0 {
		return 0
	}
	if streak <= 1 {
		return base
	}
	shift := streak - 1
	if shift > 2 {
		shift = 2
	}
	return base << shift
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
		decision.BreakerCause = breaker.snapshotCause()
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
