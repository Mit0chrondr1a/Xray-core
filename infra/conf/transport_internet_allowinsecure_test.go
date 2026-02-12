package conf

import (
	"testing"
	"time"

	tlscfg "github.com/xtls/xray-core/transport/internet/tls"
)

func TestTLSAllowInsecureBeforeRemovalDate(t *testing.T) {
	previousNow := nowForTransportConfig
	nowForTransportConfig = func() time.Time {
		return allowInsecureRemovalDate.Add(-time.Second)
	}
	defer func() { nowForTransportConfig = previousNow }()

	message, err := (&TLSConfig{AllowInsecure: true}).Build()
	if err != nil {
		t.Fatalf("expected allowInsecure to remain accepted before cutoff: %v", err)
	}
	config := message.(*tlscfg.Config)
	if !config.AllowInsecure {
		t.Fatal("expected allowInsecure to be preserved before cutoff")
	}
}

func TestTLSAllowInsecureOnRemovalDate(t *testing.T) {
	previousNow := nowForTransportConfig
	nowForTransportConfig = func() time.Time {
		return allowInsecureRemovalDate
	}
	defer func() { nowForTransportConfig = previousNow }()

	if _, err := (&TLSConfig{AllowInsecure: true}).Build(); err == nil {
		t.Fatal("expected allowInsecure to be rejected on cutoff date")
	}
}
