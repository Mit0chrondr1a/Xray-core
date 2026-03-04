package tcp

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestNativeRealityServerEligible(t *testing.T) {
	base := &Listener{
		config:            &Config{AcceptProxyProtocol: false},
		realityXrayConfig: &reality.Config{},
	}

	t.Run("native unavailable", func(t *testing.T) {
		if nativeRealityServerEligible(base, false, true, false) {
			t.Fatal("nativeRealityServerEligible should be false when native is unavailable")
		}
	})

	t.Run("full ktls unavailable", func(t *testing.T) {
		if nativeRealityServerEligible(base, true, false, false) {
			t.Fatal("nativeRealityServerEligible should be false when full kTLS is unavailable")
		}
	})

	t.Run("deferred promotion cooldown active", func(t *testing.T) {
		if nativeRealityServerEligible(base, true, true, true) {
			t.Fatal("nativeRealityServerEligible should be false when deferred promotion cooldown is active")
		}
	})

	t.Run("missing reality config", func(t *testing.T) {
		l := &Listener{config: &Config{AcceptProxyProtocol: false}}
		if nativeRealityServerEligible(l, true, true, false) {
			t.Fatal("nativeRealityServerEligible should be false when reality config is nil")
		}
	})

	t.Run("proxy protocol enabled", func(t *testing.T) {
		l := &Listener{
			config:            &Config{AcceptProxyProtocol: true},
			realityXrayConfig: &reality.Config{},
		}
		if nativeRealityServerEligible(l, true, true, false) {
			t.Fatal("nativeRealityServerEligible should be false when AcceptProxyProtocol is true")
		}
	})

	t.Run("mldsa65 seed configured", func(t *testing.T) {
		l := &Listener{
			config: &Config{AcceptProxyProtocol: false},
			realityXrayConfig: &reality.Config{
				Mldsa65Seed: make([]byte, 32),
			},
		}
		if nativeRealityServerEligible(l, true, true, false) {
			t.Fatal("nativeRealityServerEligible should be false when mldsa65_seed is configured")
		}
	})

	t.Run("eligible", func(t *testing.T) {
		if !nativeRealityServerEligible(base, true, true, false) {
			t.Fatal("nativeRealityServerEligible should be true when all requirements are met")
		}
	})
}
