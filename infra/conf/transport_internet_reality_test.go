package conf

import (
	"encoding/base64"
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
)

func validRealityServerConfig() REALITYConfig {
	return REALITYConfig{
		Dest:        []byte(`"127.0.0.1:443"`),
		ServerNames: []string{"example.com"},
		PrivateKey:  base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		ShortIds:    []string{"0123456789abcdef"},
	}
}

func TestREALITYBuildKeepsKeyRotationHoursForCompatibility(t *testing.T) {
	cfg := validRealityServerConfig()
	cfg.KeyRotationHours = 1

	msg, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build failed with keyRotationHours=%d: %v", cfg.KeyRotationHours, err)
	}
	realityConfig, ok := msg.(*reality.Config)
	if !ok {
		t.Fatalf("unexpected config type: %T", msg)
	}
	if realityConfig.GetKeyRotationHours() != cfg.KeyRotationHours {
		t.Fatalf("keyRotationHours mismatch: got %d, want %d", realityConfig.GetKeyRotationHours(), cfg.KeyRotationHours)
	}
}

func TestREALITYBuildNativePathPolicyDefaults(t *testing.T) {
	cfg := validRealityServerConfig()

	msg, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	realityConfig, ok := msg.(*reality.Config)
	if !ok {
		t.Fatalf("unexpected config type: %T", msg)
	}
	policy := realityConfig.GetNativePathPolicy()
	if policy == nil {
		t.Fatal("nativePathPolicy should be set by default")
	}
	if policy.GetMode() != reality.NativePathMode_AUTO {
		t.Fatalf("mode mismatch: got %v, want %v", policy.GetMode(), reality.NativePathMode_AUTO)
	}
	if !policy.GetAllowFallback() {
		t.Fatal("allowFallback should default to true")
	}
	if !policy.GetTelemetryEnforce() {
		t.Fatal("telemetryEnforce should default to true")
	}
	breaker := policy.GetBreaker()
	if breaker == nil {
		t.Fatal("breaker should be non-nil")
	}
	if !breaker.GetEnabled() {
		t.Fatal("breaker.enabled should default to true")
	}
}

func TestREALITYBuildNativePathPolicyOverride(t *testing.T) {
	cfg := validRealityServerConfig()
	allowFallback := false
	telemetryEnforce := false
	breakerEnabled := false
	cfg.NativePathPolicy = &NativePathPolicyConfig{
		Mode:             "FORCE_NATIVE",
		AllowFallback:    &allowFallback,
		TelemetryEnforce: &telemetryEnforce,
		Breaker: &NativePathBreakerConfig{
			Enabled:                      &breakerEnabled,
			PeekTimeoutThreshold:         5,
			InternalErrorThreshold:       7,
			WindowSeconds:                90,
			CooldownSeconds:              45,
			HalfOpenProbeIntervalSeconds: 3,
		},
	}

	msg, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	realityConfig := msg.(*reality.Config)
	policy := realityConfig.GetNativePathPolicy()
	if policy.GetMode() != reality.NativePathMode_FORCE_NATIVE {
		t.Fatalf("mode mismatch: got %v, want %v", policy.GetMode(), reality.NativePathMode_FORCE_NATIVE)
	}
	if policy.GetAllowFallback() {
		t.Fatal("allowFallback should be false when configured")
	}
	if policy.GetTelemetryEnforce() {
		t.Fatal("telemetryEnforce should be false when configured")
	}
	breaker := policy.GetBreaker()
	if breaker.GetEnabled() {
		t.Fatal("breaker.enabled should be false when configured")
	}
	if breaker.GetPeekTimeoutThreshold() != 5 {
		t.Fatalf("peekTimeoutThreshold mismatch: got %d, want 5", breaker.GetPeekTimeoutThreshold())
	}
	if breaker.GetInternalErrorThreshold() != 7 {
		t.Fatalf("internalErrorThreshold mismatch: got %d, want 7", breaker.GetInternalErrorThreshold())
	}
	if breaker.GetWindowSeconds() != 90 {
		t.Fatalf("windowSeconds mismatch: got %d, want 90", breaker.GetWindowSeconds())
	}
	if breaker.GetCooldownSeconds() != 45 {
		t.Fatalf("cooldownSeconds mismatch: got %d, want 45", breaker.GetCooldownSeconds())
	}
	if breaker.GetHalfOpenProbeIntervalSeconds() != 3 {
		t.Fatalf("halfOpenProbeIntervalSeconds mismatch: got %d, want 3", breaker.GetHalfOpenProbeIntervalSeconds())
	}
}

func TestREALITYBuildNativePathPolicyRejectsUnknownMode(t *testing.T) {
	cfg := validRealityServerConfig()
	cfg.NativePathPolicy = &NativePathPolicyConfig{Mode: "SPEED_RUN"}
	if _, err := cfg.Build(); err == nil {
		t.Fatal("expected error for invalid nativePathPolicy.mode")
	}
}

func TestREALITYBuildNativePathPolicyRejectsDisableWithNoFallback(t *testing.T) {
	cfg := validRealityServerConfig()
	allowFallback := false
	cfg.NativePathPolicy = &NativePathPolicyConfig{
		Mode:          "DISABLE_NATIVE",
		AllowFallback: &allowFallback,
	}
	if _, err := cfg.Build(); err == nil {
		t.Fatal("expected error for DISABLE_NATIVE with allowFallback=false")
	}
}
