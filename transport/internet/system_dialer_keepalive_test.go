package internet

import (
	"testing"
	"time"
)

func TestBuildTCPKeepAliveConfig_Defaults(t *testing.T) {
	keepAlive, cfg, err := buildTCPKeepAliveConfig(nil)
	if err != nil {
		t.Fatalf("buildTCPKeepAliveConfig(nil) error: %v", err)
	}
	if keepAlive != 0 {
		t.Fatalf("keepAlive=%v, want 0", keepAlive)
	}
	if !cfg.Enable {
		t.Fatal("Enable should default to true")
	}
	if cfg.Idle != 45*time.Second {
		t.Fatalf("Idle=%v, want %v", cfg.Idle, 45*time.Second)
	}
	if cfg.Interval != 45*time.Second {
		t.Fatalf("Interval=%v, want %v", cfg.Interval, 45*time.Second)
	}
	// Keep Count unset so Go won't force TCP_KEEPCNT on unsupported platforms.
	if cfg.Count != -1 {
		t.Fatalf("Count=%d, want -1", cfg.Count)
	}
}

func TestBuildTCPKeepAliveConfig_Overrides(t *testing.T) {
	keepAlive, cfg, err := buildTCPKeepAliveConfig(&SocketConfig{
		TcpKeepAliveIdle:     30,
		TcpKeepAliveInterval: 10,
	})
	if err != nil {
		t.Fatalf("buildTCPKeepAliveConfig(overrides) error: %v", err)
	}
	if keepAlive != 0 {
		t.Fatalf("keepAlive=%v, want 0", keepAlive)
	}
	if !cfg.Enable {
		t.Fatal("Enable should remain true with positive overrides")
	}
	if cfg.Idle != 30*time.Second {
		t.Fatalf("Idle=%v, want %v", cfg.Idle, 30*time.Second)
	}
	if cfg.Interval != 10*time.Second {
		t.Fatalf("Interval=%v, want %v", cfg.Interval, 10*time.Second)
	}
	if cfg.Count != -1 {
		t.Fatalf("Count=%d, want -1", cfg.Count)
	}
}

func TestBuildTCPKeepAliveConfig_DisablesKeepAlive(t *testing.T) {
	keepAlive, cfg, err := buildTCPKeepAliveConfig(&SocketConfig{
		TcpKeepAliveIdle: -1,
	})
	if err != nil {
		t.Fatalf("buildTCPKeepAliveConfig(disable) error: %v", err)
	}
	if keepAlive != -1 {
		t.Fatalf("keepAlive=%v, want -1", keepAlive)
	}
	if cfg.Enable {
		t.Fatal("Enable should be false when keepalive is disabled")
	}
}

func TestBuildTCPKeepAliveConfig_RejectsMixedSigns(t *testing.T) {
	_, _, err := buildTCPKeepAliveConfig(&SocketConfig{
		TcpKeepAliveIdle:     -1,
		TcpKeepAliveInterval: 10,
	})
	if err == nil {
		t.Fatal("expected error for mixed-sign keepalive values")
	}
}

func TestHasMixedSignKeepAliveValues(t *testing.T) {
	tests := []struct {
		idle     int32
		interval int32
		want     bool
	}{
		{idle: -1, interval: 10, want: true},
		{idle: 10, interval: -1, want: true},
		{idle: -1, interval: -1, want: false},
		{idle: 10, interval: 10, want: false},
		{idle: 0, interval: -1, want: false},
		{idle: -1, interval: 0, want: false},
	}
	for _, tt := range tests {
		got := hasMixedSignKeepAliveValues(tt.idle, tt.interval)
		if got != tt.want {
			t.Fatalf("hasMixedSignKeepAliveValues(%d, %d)=%v, want %v", tt.idle, tt.interval, got, tt.want)
		}
	}
}
