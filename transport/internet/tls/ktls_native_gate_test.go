//go:build linux

package tls

import "testing"

func TestNativeTLSConfigVersions(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *Config
		wantTLS12 bool
		wantTLS13 bool
	}{
		{
			name:      "nil config defaults to tls12 and tls13",
			cfg:       nil,
			wantTLS12: true,
			wantTLS13: true,
		},
		{
			name:      "tls13 only",
			cfg:       &Config{MinVersion: "1.3"},
			wantTLS12: false,
			wantTLS13: true,
		},
		{
			name:      "tls12 only",
			cfg:       &Config{MaxVersion: "1.2"},
			wantTLS12: true,
			wantTLS13: false,
		},
		{
			name:      "unsupported range falls back to tls13",
			cfg:       &Config{MinVersion: "1.0", MaxVersion: "1.1"},
			wantTLS12: false,
			wantTLS13: true,
		},
		{
			name:      "inverted range falls back to tls13",
			cfg:       &Config{MinVersion: "1.3", MaxVersion: "1.2"},
			wantTLS12: false,
			wantTLS13: true,
		},
		{
			name:      "invalid strings keep defaults",
			cfg:       &Config{MinVersion: "invalid"},
			wantTLS12: true,
			wantTLS13: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTLS12, gotTLS13 := nativeTLSConfigVersions(tt.cfg)
			if gotTLS12 != tt.wantTLS12 || gotTLS13 != tt.wantTLS13 {
				t.Fatalf("nativeTLSConfigVersions() = (tls12=%v, tls13=%v), want (tls12=%v, tls13=%v)",
					gotTLS12, gotTLS13, tt.wantTLS12, tt.wantTLS13)
			}
		})
	}
}
