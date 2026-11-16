package reality

import (
	"os"
	"strings"
)

// NativePathModeEnv overrides the configured native path mode for every
// REALITY listener in the process.
const NativePathModeEnv = "XRAY_DEBUG_NATIVE_REALITY_MODE"

// NativePathDisableEnv force-disables the native REALITY server path.
const NativePathDisableEnv = "XRAY_DEBUG_DISABLE_NATIVE_REALITY"

// NativePathModeOverride parses NativePathModeEnv. The second result is false
// when the variable is unset or not a known mode.
func NativePathModeOverride() (NativePathMode, bool) {
	raw := strings.TrimSpace(os.Getenv(NativePathModeEnv))
	if raw == "" {
		return NativePathMode_AUTO, false
	}
	switch strings.ToUpper(strings.ReplaceAll(raw, "-", "_")) {
	case "AUTO":
		return NativePathMode_AUTO, true
	case "PREFER_NATIVE", "PREFER":
		return NativePathMode_PREFER_NATIVE, true
	case "FORCE_NATIVE", "FORCE":
		return NativePathMode_FORCE_NATIVE, true
	case "DISABLE_NATIVE", "DISABLE", "OFF":
		return NativePathMode_DISABLE_NATIVE, true
	default:
		return NativePathMode_AUTO, false
	}
}

// EffectiveNativePathMode returns the native path mode of cfg after applying
// the environment override. A missing policy means AUTO.
func EffectiveNativePathMode(cfg *Config) NativePathMode {
	mode := NativePathMode_AUTO
	if cfg != nil && cfg.GetNativePathPolicy() != nil {
		mode = cfg.GetNativePathPolicy().GetMode()
	}
	if override, ok := NativePathModeOverride(); ok {
		mode = override
	}
	return mode
}

// NativeServerHandshakeOptedIn reports whether the operator explicitly asked
// for the rustls REALITY server handshake (PREFER_NATIVE or FORCE_NATIVE).
//
// The default, AUTO, must keep the Go REALITY handshake. Go REALITY shapes the
// handshake of every authenticated session after the real target: it reuses
// the target's ServerHello (cipher suite, key-share group including
// X25519MLKEM768), pads its handshake records to the target's record lengths
// and replays the target's post-handshake record lengths. The rustls handshake
// never contacts the target and does none of that, so an on-path observer can
// tell the two apart without probing. Until the native path reproduces that
// shaping it is an explicit trade of camouflage for speed, never a default.
func NativeServerHandshakeOptedIn(cfg *Config) bool {
	if os.Getenv(NativePathDisableEnv) == "1" {
		return false
	}
	switch EffectiveNativePathMode(cfg) {
	case NativePathMode_PREFER_NATIVE, NativePathMode_FORCE_NATIVE:
		return true
	default:
		return false
	}
}
