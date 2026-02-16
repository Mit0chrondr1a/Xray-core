package socks

import (
	"testing"
	"time"
)

type testAddr string

func (a testAddr) Network() string { return "udp" }
func (a testAddr) String() string  { return string(a) }

func countFilterEntries(f *UDPFilter) int {
	count := 0
	f.ips.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func TestUDPFilterTTLExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	filter := NewUDPFilter(2 * time.Second)
	filter.now = func() time.Time { return now }
	filter.cleanupEvery = 1

	if !filter.Add(testAddr("203.0.113.5:12345")) {
		t.Fatal("failed to add authenticated UDP source")
	}
	if !filter.Check(testAddr("203.0.113.5:45678")) {
		t.Fatal("expected UDP source to be authorized before TTL expiry")
	}

	now = now.Add(3 * time.Second)
	if filter.Check(testAddr("203.0.113.5:7890")) {
		t.Fatal("expected UDP source to expire after TTL")
	}
}

func TestUDPFilterSlidingExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	filter := NewUDPFilter(2 * time.Second)
	filter.now = func() time.Time { return now }
	filter.cleanupEvery = 1

	filter.Add(testAddr("198.51.100.1:1000"))
	now = now.Add(1 * time.Second)
	if !filter.Check(testAddr("198.51.100.1:2000")) {
		t.Fatal("expected check to succeed and refresh TTL")
	}

	now = now.Add(1500 * time.Millisecond)
	if !filter.Check(testAddr("198.51.100.1:3000")) {
		t.Fatal("expected refreshed entry to remain valid")
	}
}

func TestUDPFilterCleanupRemovesExpired(t *testing.T) {
	now := time.Unix(1700000000, 0)
	filter := NewUDPFilter(1 * time.Second)
	filter.now = func() time.Time { return now }
	filter.cleanupEvery = 1

	filter.Add(testAddr("192.0.2.10:1000"))
	filter.Add(testAddr("192.0.2.20:1000"))

	now = now.Add(2 * time.Second)
	if filter.Check(testAddr("192.0.2.10:1000")) {
		t.Fatal("expected expired source to fail authorization")
	}
	if entries := countFilterEntries(filter); entries != 0 {
		t.Fatalf("expected cleanup to remove expired entries, got %d", entries)
	}
}

func TestUDPFilterNilAddr(t *testing.T) {
	filter := NewUDPFilter(10 * time.Second)
	if filter.Add(nil) {
		t.Fatal("Add(nil) should return false")
	}
	if filter.Check(nil) {
		t.Fatal("Check(nil) should return false")
	}
}

func TestUDPFilterMalformedAddr(t *testing.T) {
	filter := NewUDPFilter(10 * time.Second)
	// Address without port -- SplitHostPort will fail.
	if filter.Add(testAddr("192.0.2.1")) {
		t.Fatal("Add with malformed addr should return false")
	}
	if filter.Check(testAddr("192.0.2.1")) {
		t.Fatal("Check with malformed addr should return false")
	}
}

func TestUDPFilterDifferentPorts(t *testing.T) {
	filter := NewUDPFilter(10 * time.Second)
	filter.Add(testAddr("10.0.0.1:5000"))
	// Same IP, different port should still pass (IP-based tracking).
	if !filter.Check(testAddr("10.0.0.1:6000")) {
		t.Fatal("same IP with different port should pass")
	}
}

func TestUDPFilterMultipleIPs(t *testing.T) {
	filter := NewUDPFilter(10 * time.Second)
	filter.Add(testAddr("10.0.0.1:5000"))
	filter.Add(testAddr("10.0.0.2:5000"))
	if !filter.Check(testAddr("10.0.0.1:9999")) {
		t.Fatal("first IP should be authorized")
	}
	if !filter.Check(testAddr("10.0.0.2:9999")) {
		t.Fatal("second IP should be authorized")
	}
	if filter.Check(testAddr("10.0.0.3:9999")) {
		t.Fatal("third IP was never added, should fail")
	}
}

func TestUDPFilterDefaultTTL(t *testing.T) {
	filter := NewUDPFilter(0)
	if filter.ttl != defaultUDPFilterTTL {
		t.Fatalf("default TTL=%v, want %v", filter.ttl, defaultUDPFilterTTL)
	}
}

func TestUDPFilterNegativeTTL(t *testing.T) {
	filter := NewUDPFilter(-1 * time.Second)
	if filter.ttl != defaultUDPFilterTTL {
		t.Fatalf("negative TTL should clamp to default: got %v", filter.ttl)
	}
}

func TestIpFromAddr(t *testing.T) {
	tests := []struct {
		name   string
		addr   testAddr
		wantIP string
		wantOK bool
	}{
		{"valid", testAddr("10.0.0.1:80"), "10.0.0.1", true},
		{"ipv6", testAddr("[::1]:80"), "::1", true},
		{"no port", testAddr("10.0.0.1"), "", false},
		{"empty", testAddr(""), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := ipFromAddr(tt.addr)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v, want %v", ok, tt.wantOK)
			}
			if ip != tt.wantIP {
				t.Fatalf("ip=%q, want %q", ip, tt.wantIP)
			}
		})
	}
}
