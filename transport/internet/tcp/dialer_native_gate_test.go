package tcp

import (
	gotls "crypto/tls"
	"slices"
	"testing"

	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestShouldUseNativeTLSClient(t *testing.T) {
	savedNativeAvailableFn := nativeAvailableFn
	savedNativeFullKTLSFn := nativeFullKTLSSupportedForTLSConfigFn
	defer func() {
		nativeAvailableFn = savedNativeAvailableFn
		nativeFullKTLSSupportedForTLSConfigFn = savedNativeFullKTLSFn
	}()

	cfg := &xtls.Config{MinVersion: "1.3"}
	var gotCfg *xtls.Config

	nativeAvailableFn = func() bool { return true }
	nativeFullKTLSSupportedForTLSConfigFn = func(c *xtls.Config) bool {
		gotCfg = c
		return false
	}
	if shouldUseNativeTLSClient(cfg) {
		t.Fatal("expected native TLS client path to be disabled when full kTLS is unavailable")
	}
	if gotCfg != cfg {
		t.Fatal("expected native full kTLS probe to receive the effective runtime config")
	}

	nativeFullKTLSSupportedForTLSConfigFn = func(*xtls.Config) bool { return true }
	if !shouldUseNativeTLSClient(cfg) {
		t.Fatal("expected native TLS client path when native is available and full kTLS is supported")
	}

	nativeAvailableFn = func() bool { return false }
	if shouldUseNativeTLSClient(cfg) {
		t.Fatal("expected native TLS client path to be disabled when native runtime is unavailable")
	}
}

func TestNativeTLSConfigWithRuntimeOverrides(t *testing.T) {
	base := &xtls.Config{
		ServerName:           "frommitm",
		NextProtocol:         []string{"frommitm"},
		VerifyPeerCertByName: []string{"frommitm"},
	}
	runtimeRand := &xtls.RandCarrier{
		VerifyPeerCertByName: []string{"fronting.example.com", "example.com"},
	}
	runtime := &gotls.Config{
		ServerName: "fronting.example.com",
		NextProtos: []string{"h2", "http/1.1"},
		Rand:       runtimeRand,
	}

	got := nativeTLSConfigWithRuntimeOverrides(base, runtime)
	if got == base {
		t.Fatal("expected a copied native config when runtime overrides are present")
	}
	if got.ServerName != "fronting.example.com" {
		t.Fatalf("expected runtime SNI override, got %q", got.ServerName)
	}
	if !slices.Equal(got.NextProtocol, runtime.NextProtos) {
		t.Fatalf("expected runtime ALPN override, got %v", got.NextProtocol)
	}
	if !slices.Equal(got.VerifyPeerCertByName, runtimeRand.VerifyPeerCertByName) {
		t.Fatalf("expected runtime verify-name override, got %v", got.VerifyPeerCertByName)
	}

	// Ensure cloned slices are detached from runtime tls.Config buffers.
	runtime.NextProtos[0] = "mutated"
	runtimeRand.VerifyPeerCertByName[0] = "mutated"
	if got.NextProtocol[0] == "mutated" {
		t.Fatal("expected native config ALPN slice to be cloned")
	}
	if got.VerifyPeerCertByName[0] == "mutated" {
		t.Fatal("expected native config verify-name slice to be cloned")
	}

	// Ensure original config stays untouched.
	if base.ServerName != "frommitm" {
		t.Fatalf("base config server_name mutated: %q", base.ServerName)
	}
	if !slices.Equal(base.NextProtocol, []string{"frommitm"}) {
		t.Fatalf("base config next_protocol mutated: %v", base.NextProtocol)
	}
	if !slices.Equal(base.VerifyPeerCertByName, []string{"frommitm"}) {
		t.Fatalf("base config verify_peer_cert_by_name mutated: %v", base.VerifyPeerCertByName)
	}
}

func TestNativeTLSConfigWithRuntimeOverridesNilRuntime(t *testing.T) {
	base := &xtls.Config{ServerName: "example.com"}
	if got := nativeTLSConfigWithRuntimeOverrides(base, nil); got != base {
		t.Fatal("expected original config when runtime config is nil")
	}
}
