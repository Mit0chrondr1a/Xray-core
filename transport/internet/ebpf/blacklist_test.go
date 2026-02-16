package ebpf

import (
	"net"
	"testing"
	"time"
)

// --- IPToKey ---

func TestIPToKeyIPv4(t *testing.T) {
	key := IPToKey(net.ParseIP("192.168.1.1"))
	// IPv4-mapped IPv6: bytes [10],[11] = 0xff,0xff; [12:16] = IP
	if key[10] != 0xff || key[11] != 0xff {
		t.Fatalf("IPv4-mapped prefix missing: got %x", key[:12])
	}
	if key[12] != 192 || key[13] != 168 || key[14] != 1 || key[15] != 1 {
		t.Fatalf("IPv4 bytes wrong: got %v", key[12:16])
	}
}

func TestIPToKeyIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	key := IPToKey(ip)
	expected := ip.To16()
	for i := 0; i < 16; i++ {
		if key[i] != expected[i] {
			t.Fatalf("IPv6 key byte %d: got %02x, want %02x", i, key[i], expected[i])
		}
	}
}

func TestIPToKeyNil(t *testing.T) {
	key := IPToKey(nil)
	var zero [16]byte
	if key != zero {
		t.Fatalf("nil IP should produce zero key, got %v", key)
	}
}

// --- DefaultBlacklistConfig ---

func TestDefaultBlacklistConfig(t *testing.T) {
	cfg := DefaultBlacklistConfig()
	if cfg.MaxEntries != 4096 {
		t.Fatalf("MaxEntries=%d, want 4096", cfg.MaxEntries)
	}
	if cfg.FailThreshold != 5 {
		t.Fatalf("FailThreshold=%d, want 5", cfg.FailThreshold)
	}
	if cfg.FailWindow != 60*time.Second {
		t.Fatalf("FailWindow=%v, want 60s", cfg.FailWindow)
	}
	if cfg.BanDuration != 5*time.Minute {
		t.Fatalf("BanDuration=%v, want 5m", cfg.BanDuration)
	}
	if cfg.CleanupInterval != 30*time.Second {
		t.Fatalf("CleanupInterval=%v, want 30s", cfg.CleanupInterval)
	}
}

// --- BlacklistManager ---

func TestBlacklistManagerRecordFailureAndBan(t *testing.T) {
	cfg := DefaultBlacklistConfig()
	cfg.FailThreshold = 3
	cfg.FailWindow = 10 * time.Second
	cfg.BanDuration = 1 * time.Second
	cfg.CleanupInterval = 100 * time.Millisecond
	mgr := NewBlacklistManager(cfg)
	defer mgr.Disable()

	ip := net.ParseIP("10.0.0.1")

	// Before threshold, should not be banned.
	mgr.RecordFailure(ip)
	mgr.RecordFailure(ip)
	if mgr.IsBanned(ip) {
		t.Fatal("should not be banned before reaching threshold")
	}

	// Third failure should trigger ban.
	mgr.RecordFailure(ip)
	if !mgr.IsBanned(ip) {
		t.Fatal("should be banned after reaching threshold")
	}
}

func TestBlacklistManagerBanExpires(t *testing.T) {
	cfg := DefaultBlacklistConfig()
	cfg.FailThreshold = 1
	cfg.BanDuration = 50 * time.Millisecond
	cfg.CleanupInterval = 10 * time.Millisecond
	mgr := NewBlacklistManager(cfg)
	defer mgr.Disable()

	ip := net.ParseIP("10.0.0.2")
	mgr.RecordFailure(ip)
	if !mgr.IsBanned(ip) {
		t.Fatal("should be banned immediately after threshold")
	}

	time.Sleep(100 * time.Millisecond)
	if mgr.IsBanned(ip) {
		t.Fatal("ban should have expired")
	}
}

func TestBlacklistManagerNilIP(t *testing.T) {
	mgr := NewBlacklistManager(DefaultBlacklistConfig())
	defer mgr.Disable()

	// Should not panic on nil IP.
	mgr.RecordFailure(nil)
	if mgr.IsBanned(nil) {
		t.Fatal("nil IP should not be banned")
	}
}

func TestBlacklistManagerIsBannedFalseForUnknown(t *testing.T) {
	mgr := NewBlacklistManager(DefaultBlacklistConfig())
	defer mgr.Disable()

	if mgr.IsBanned(net.ParseIP("1.2.3.4")) {
		t.Fatal("unknown IP should not be banned")
	}
}

func TestBlacklistManagerRecordFailureAlreadyBanned(t *testing.T) {
	cfg := DefaultBlacklistConfig()
	cfg.FailThreshold = 1
	cfg.BanDuration = 1 * time.Second
	mgr := NewBlacklistManager(cfg)
	defer mgr.Disable()

	ip := net.ParseIP("10.0.0.3")
	mgr.RecordFailure(ip)
	if !mgr.IsBanned(ip) {
		t.Fatal("should be banned")
	}

	// Recording more failures on an already-banned IP should be a no-op.
	mgr.RecordFailure(ip)
	if !mgr.IsBanned(ip) {
		t.Fatal("should still be banned")
	}
}

func TestBlacklistManagerSweepExpired(t *testing.T) {
	cfg := DefaultBlacklistConfig()
	cfg.FailThreshold = 1
	cfg.BanDuration = 10 * time.Millisecond
	mgr := NewBlacklistManager(cfg)

	ip := net.ParseIP("172.16.0.1")
	mgr.RecordFailure(ip)
	time.Sleep(20 * time.Millisecond)
	mgr.sweepExpired()

	mgr.mu.Lock()
	_, stillBanned := mgr.banned[IPToKey(ip)]
	mgr.mu.Unlock()
	if stillBanned {
		t.Fatal("sweepExpired should have removed expired ban")
	}
}

func TestBlacklistManagerEnableNonLinux(t *testing.T) {
	// On Linux this will attempt XDP; on non-Linux it returns ErrXDPNotSupported.
	// Either way, it should not panic.
	mgr := NewBlacklistManager(DefaultBlacklistConfig())
	err := mgr.Enable("lo")
	if err != nil {
		t.Logf("Enable returned expected error: %v", err)
	}
	mgr.Disable()
}

func TestBlacklistManagerFailureWindowPruning(t *testing.T) {
	cfg := DefaultBlacklistConfig()
	cfg.FailThreshold = 3
	cfg.FailWindow = 50 * time.Millisecond
	mgr := NewBlacklistManager(cfg)
	defer mgr.Disable()

	ip := net.ParseIP("10.0.0.4")
	// Two failures, then wait for window to expire.
	mgr.RecordFailure(ip)
	mgr.RecordFailure(ip)
	time.Sleep(60 * time.Millisecond)

	// Old failures should be pruned, so this is only the first in a new window.
	mgr.RecordFailure(ip)
	if mgr.IsBanned(ip) {
		t.Fatal("old failures should have been pruned, IP should not be banned")
	}
}
