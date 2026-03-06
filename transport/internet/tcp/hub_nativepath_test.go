package tcp

import (
	"net"
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestNativeRealityServerEligible(t *testing.T) {
	base := &Listener{
		config:            &Config{AcceptProxyProtocol: false},
		realityXrayConfig: &reality.Config{},
	}
	oldAvail := nativeEligibilityAvailableFn
	oldKTLS := nativeEligibilityFullKTLSSupportedFn
	nativeEligibilityAvailableFn = func() bool { return true }
	nativeEligibilityFullKTLSSupportedFn = func() bool { return true }
	t.Cleanup(func() {
		nativeEligibilityAvailableFn = oldAvail
		nativeEligibilityFullKTLSSupportedFn = oldKTLS
	})

	t.Run("native unavailable", func(t *testing.T) {
		if nativeRealityServerEligibleInternal(base, false, true) {
			t.Fatal("nativeRealityServerEligible should be false when native is unavailable")
		}
	})

	t.Run("full ktls unavailable", func(t *testing.T) {
		if nativeRealityServerEligibleInternal(base, true, false) {
			t.Fatal("nativeRealityServerEligible should be false when full kTLS is unavailable")
		}
	})

	t.Run("missing reality config", func(t *testing.T) {
		l := &Listener{config: &Config{AcceptProxyProtocol: false}}
		if nativeRealityServerEligibleInternal(l, true, true) {
			t.Fatal("nativeRealityServerEligible should be false when reality config is nil")
		}
	})

	t.Run("proxy protocol enabled", func(t *testing.T) {
		l := &Listener{
			config:            &Config{AcceptProxyProtocol: true},
			realityXrayConfig: &reality.Config{},
		}
		if nativeRealityServerEligibleInternal(l, true, true) {
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
		if nativeRealityServerEligibleInternal(l, true, true) {
			t.Fatal("nativeRealityServerEligible should be false when mldsa65_seed is configured")
		}
	})

	t.Run("eligible", func(t *testing.T) {
		if !nativeRealityServerEligibleInternal(base, true, true) {
			t.Fatal("nativeRealityServerEligible should be true when all requirements are met")
		}
	})

	t.Run("loopback listener auto skip is handled at decision layer", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		l := &Listener{
			listener:          ln,
			config:            &Config{AcceptProxyProtocol: false},
			realityXrayConfig: &reality.Config{},
		}
		if !nativeRealityServerEligibleInternal(l, true, true) {
			t.Fatal("eligibility should remain true; loopback guard belongs to decision layer, not capability layer")
		}
	})
}
