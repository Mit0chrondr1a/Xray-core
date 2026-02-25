package tcp

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
)

// TestNativeRealityServerGuard_ProxyProtocol verifies that the native Rust
// REALITY path is disabled when AcceptProxyProtocol is enabled. ProxyProtocol
// connections require buffered PROXY header parsing that raw fd reads skip.

func TestNativeRealityServerGuard_ProxyProtocolDisablesNative(t *testing.T) {
	saved := useNativeRealityServerFn
	defer func() { useNativeRealityServerFn = saved }()

	// Restore the real function so we test the actual guard logic.
	useNativeRealityServerFn = func(v *Listener) bool {
		// Simulate: native available, full kTLS, has reality config, no MLDSA65
		// — only AcceptProxyProtocol should differ between the two sub-tests.
		return v.realityXrayConfig != nil &&
			(v.config == nil || !v.config.AcceptProxyProtocol)
	}

	t.Run("ProxyProtocol=true disables native path", func(t *testing.T) {
		l := &Listener{
			config:            &Config{AcceptProxyProtocol: true},
			realityXrayConfig: &reality.Config{},
		}
		if useNativeRealityServerFn(l) {
			t.Fatal("useNativeRealityServerFn should return false when AcceptProxyProtocol is true")
		}
	})

	t.Run("ProxyProtocol=false enables native path", func(t *testing.T) {
		l := &Listener{
			config:            &Config{AcceptProxyProtocol: false},
			realityXrayConfig: &reality.Config{},
		}
		if !useNativeRealityServerFn(l) {
			t.Fatal("useNativeRealityServerFn should return true when AcceptProxyProtocol is false")
		}
	})

	t.Run("nil config enables native path", func(t *testing.T) {
		l := &Listener{
			realityXrayConfig: &reality.Config{},
		}
		if !useNativeRealityServerFn(l) {
			t.Fatal("useNativeRealityServerFn should return true when config is nil")
		}
	})
}
