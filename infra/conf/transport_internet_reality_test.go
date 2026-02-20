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
