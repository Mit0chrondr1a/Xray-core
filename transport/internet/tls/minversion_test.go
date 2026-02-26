package tls_test

import (
	gotls "crypto/tls"
	"testing"

	. "github.com/xtls/xray-core/transport/internet/tls"
)

// TestGetTLSConfig_MinVersion_Compatibility verifies explicit legacy versions
// are honored for backward compatibility, while unknown values still default to TLS 1.2.
func TestGetTLSConfig_MinVersion_Compatibility(t *testing.T) {
	tests := []struct {
		name           string
		minVersion     string
		wantMinVersion uint16
	}{
		{
			name:           "TLS 1.0 stays TLS 1.0",
			minVersion:     "1.0",
			wantMinVersion: gotls.VersionTLS10,
		},
		{
			name:           "TLS 1.1 stays TLS 1.1",
			minVersion:     "1.1",
			wantMinVersion: gotls.VersionTLS11,
		},
		{
			name:           "TLS 1.2 stays TLS 1.2",
			minVersion:     "1.2",
			wantMinVersion: gotls.VersionTLS12,
		},
		{
			name:           "TLS 1.3 stays TLS 1.3",
			minVersion:     "1.3",
			wantMinVersion: gotls.VersionTLS13,
		},
		{
			name:           "empty string defaults to TLS 1.2",
			minVersion:     "",
			wantMinVersion: gotls.VersionTLS12,
		},
		{
			name:           "invalid string defaults to TLS 1.2",
			minVersion:     "invalid",
			wantMinVersion: gotls.VersionTLS12,
		},
		{
			name:           "version 0.9 defaults to TLS 1.2",
			minVersion:     "0.9",
			wantMinVersion: gotls.VersionTLS12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{MinVersion: tt.minVersion}
			tlsConfig := cfg.GetTLSConfig()
			if tlsConfig.MinVersion != tt.wantMinVersion {
				t.Fatalf("MinVersion=%q: got tls version 0x%04x, want 0x%04x",
					tt.minVersion, tlsConfig.MinVersion, tt.wantMinVersion)
			}
		})
	}
}

// TestGetTLSConfig_MaxVersion_Compatibility verifies explicit MaxVersion values
// are respected, including legacy values.
func TestGetTLSConfig_MaxVersion_Compatibility(t *testing.T) {
	tests := []struct {
		name           string
		maxVersion     string
		wantMaxVersion uint16
	}{
		{
			name:           "MaxVersion 1.0",
			maxVersion:     "1.0",
			wantMaxVersion: gotls.VersionTLS10,
		},
		{
			name:           "MaxVersion 1.1",
			maxVersion:     "1.1",
			wantMaxVersion: gotls.VersionTLS11,
		},
		{
			name:           "MaxVersion 1.2",
			maxVersion:     "1.2",
			wantMaxVersion: gotls.VersionTLS12,
		},
		{
			name:           "MaxVersion 1.3",
			maxVersion:     "1.3",
			wantMaxVersion: gotls.VersionTLS13,
		},
		{
			name:           "empty MaxVersion defaults to 0 (no cap)",
			maxVersion:     "",
			wantMaxVersion: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{MaxVersion: tt.maxVersion}
			tlsConfig := cfg.GetTLSConfig()
			if tlsConfig.MaxVersion != tt.wantMaxVersion {
				t.Fatalf("MaxVersion=%q: got 0x%04x, want 0x%04x",
					tt.maxVersion, tlsConfig.MaxVersion, tt.wantMaxVersion)
			}
		})
	}
}

// TestGetTLSConfig_NilConfig_Panics documents that GetTLSConfig panics on nil
// receiver. The code at config.go:506 calls c.getCertPool() before the nil
// guard at line 511, causing a nil pointer dereference. This is a latent bug.
func TestGetTLSConfig_NilConfig_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil Config.GetTLSConfig(), got none -- " +
				"if the nil-check was fixed, update this test to verify the returned config")
		}
	}()
	var cfg *Config
	_ = cfg.GetTLSConfig()
}

func TestGetTLSConfig_ExplicitLegacyBoundsArePreserved(t *testing.T) {
	cfg := &Config{
		MinVersion: "1.0",
		MaxVersion: "1.1",
	}
	tlsConfig := cfg.GetTLSConfig()
	if tlsConfig.MinVersion != gotls.VersionTLS10 {
		t.Fatalf("MinVersion got 0x%04x, want 0x%04x", tlsConfig.MinVersion, gotls.VersionTLS10)
	}
	if tlsConfig.MaxVersion != gotls.VersionTLS11 {
		t.Fatalf("MaxVersion got 0x%04x, want 0x%04x", tlsConfig.MaxVersion, gotls.VersionTLS11)
	}
}
