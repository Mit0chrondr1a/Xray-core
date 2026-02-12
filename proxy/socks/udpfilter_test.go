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
